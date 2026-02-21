import { eq, sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { userPoints } from "../core/database/schema/index.js";
import { getIO, emitToUser } from "../socket/index.js";
import { emitNotification } from "../socket/handlers/notifications.handler.js";

// XP thresholds for each level
const LEVEL_THRESHOLDS = [
  0,      // Level 1
  100,    // Level 2
  250,    // Level 3
  500,    // Level 4
  1000,   // Level 5
  1750,   // Level 6
  2750,   // Level 7
  4000,   // Level 8
  5500,   // Level 9
  7500,   // Level 10
  10000,  // Level 11+
];

// XP rewards for different actions
export const XP_REWARDS = {
  LESSON_COMPLETE: 10,
  QUIZ_PASS: 20,
  QUIZ_PERFECT: 50,
  ASSIGNMENT_COMPLETE: 15,
  STUDY_SESSION_30MIN: 5,
  DAILY_STREAK: 5,
  BADGE_EARNED: 50,
  CHALLENGE_COMPLETE: 25,
} as const;

export interface UserPointsData {
  totalXp: number;
  level: number;
  weeklyXp: number;
  monthlyXp: number;
  xpToNextLevel: number;
  levelProgress: number;
}

/**
 * Calculate level from total XP
 */
function calculateLevel(totalXp: number): number {
  for (let i = LEVEL_THRESHOLDS.length - 1; i >= 0; i--) {
    if (totalXp >= LEVEL_THRESHOLDS[i]) {
      return i + 1;
    }
  }
  return 1;
}

/**
 * Get XP required for next level
 */
function getXpForNextLevel(level: number): number {
  if (level >= LEVEL_THRESHOLDS.length) {
    // After max defined level, each level requires 2500 more XP
    return LEVEL_THRESHOLDS[LEVEL_THRESHOLDS.length - 1] + (level - LEVEL_THRESHOLDS.length + 1) * 2500;
  }
  return LEVEL_THRESHOLDS[level];
}

/**
 * Get current level threshold
 */
function getCurrentLevelThreshold(level: number): number {
  if (level <= 1) return 0;
  if (level > LEVEL_THRESHOLDS.length) {
    return LEVEL_THRESHOLDS[LEVEL_THRESHOLDS.length - 1] + (level - LEVEL_THRESHOLDS.length) * 2500;
  }
  return LEVEL_THRESHOLDS[level - 1];
}

/**
 * Get user points or create initial record
 */
export async function getUserPoints(userId: string): Promise<UserPointsData> {
  const result = await db
    .select()
    .from(userPoints)
    .where(eq(userPoints.userId, userId))
    .limit(1);

  let points = result[0];

  if (!points) {
    // Create initial points record
    const [created] = await db
      .insert(userPoints)
      .values({
        userId,
        totalXp: 0,
        level: 1,
        weeklyXp: 0,
        monthlyXp: 0,
      })
      .returning();
    points = created;
  }

  const currentThreshold = getCurrentLevelThreshold(points.level);
  const nextThreshold = getXpForNextLevel(points.level);
  const xpInCurrentLevel = points.totalXp - currentThreshold;
  const xpNeededForLevel = nextThreshold - currentThreshold;

  return {
    totalXp: points.totalXp,
    level: points.level,
    weeklyXp: points.weeklyXp,
    monthlyXp: points.monthlyXp,
    xpToNextLevel: nextThreshold - points.totalXp,
    levelProgress: Math.min(100, Math.round((xpInCurrentLevel / xpNeededForLevel) * 100)),
  };
}

/**
 * Award XP to a user
 */
export async function awardXp(
  userId: string,
  amount: number,
  reason: string
): Promise<{ newTotal: number; leveledUp: boolean; newLevel: number }> {
  // Get current points
  const current = await getUserPoints(userId);
  const newTotal = current.totalXp + amount;
  const newLevel = calculateLevel(newTotal);
  const leveledUp = newLevel > current.level;

  // Update points
  await db
    .update(userPoints)
    .set({
      totalXp: newTotal,
      level: newLevel,
      weeklyXp: current.weeklyXp + amount,
      monthlyXp: current.monthlyXp + amount,
      lastXpAwardedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(userPoints.userId, userId));

  // Emit real-time notification
  try {
    const io = getIO();

    // Send XP award notification
    emitNotification(io, userId, {
      id: Date.now(),
      type: "xp",
      title: `+${amount} XP`,
      message: reason,
      createdAt: new Date().toISOString(),
    });

    // Send level up notification if applicable
    if (leveledUp) {
      emitNotification(io, userId, {
        id: Date.now() + 1,
        type: "level_up",
        title: `Level Up!`,
        message: `Congratulations! You reached Level ${newLevel}`,
        createdAt: new Date().toISOString(),
      });
    }
  } catch (error) {
    // Socket not initialized, skip real-time notifications
    console.log("[awardXp] Socket not available for real-time notifications");
  }

  return { newTotal, leveledUp, newLevel };
}

/**
 * Reset weekly XP (call every Sunday)
 */
export async function resetWeeklyXp(): Promise<void> {
  await db
    .update(userPoints)
    .set({ weeklyXp: 0, updatedAt: new Date() });
}

/**
 * Reset monthly XP (call on 1st of each month)
 */
export async function resetMonthlyXp(): Promise<void> {
  await db
    .update(userPoints)
    .set({ monthlyXp: 0, updatedAt: new Date() });
}

/**
 * Get leaderboard by XP
 */
export async function getXpLeaderboard(limit = 10): Promise<Array<{
  userId: string;
  totalXp: number;
  level: number;
  rank: number;
}>> {
  const results = await db
    .select({
      userId: userPoints.userId,
      totalXp: userPoints.totalXp,
      level: userPoints.level,
    })
    .from(userPoints)
    .orderBy(sql`${userPoints.totalXp} DESC`)
    .limit(limit);

  return results.map((r, index) => ({
    ...r,
    rank: index + 1,
  }));
}
