import { and, eq, gte, lte, sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { challenges, userChallenges, studySessions, quizAttempts, progressTracking } from "../core/database/schema/index.js";
import { awardXp, XP_REWARDS } from "./points.service.js";
import { getIO } from "../socket/index.js";
import { emitNotification } from "../socket/handlers/notifications.handler.js";

export interface ChallengeData {
  id: number;
  title: string;
  description: string | null;
  type: "daily" | "weekly" | "special";
  xpReward: number;
  targetValue: number;
  currentValue: number;
  status: "active" | "completed" | "expired";
  startedAt: string;
  completedAt: string | null;
  endsAt: string | null;
}

/**
 * Get active challenges for a user
 */
export async function getUserChallenges(userId: string): Promise<ChallengeData[]> {
  const now = new Date();

  // Get all active challenges
  const activeChallenges = await db
    .select()
    .from(challenges)
    .where(
      and(
        eq(challenges.isActive, true),
        lte(challenges.startsAt, now),
        gte(challenges.endsAt, now)
      )
    );

  // Get user's progress on these challenges
  const userProgress = await db
    .select()
    .from(userChallenges)
    .where(eq(userChallenges.userId, userId));

  const progressMap = new Map(
    userProgress.map((p) => [p.challengeId, p])
  );

  // Combine challenge data with user progress
  const result: ChallengeData[] = [];

  for (const challenge of activeChallenges) {
    const progress = progressMap.get(challenge.id);

    if (progress) {
      // User has started this challenge
      result.push({
        id: challenge.id,
        title: challenge.title,
        description: challenge.description,
        type: challenge.type,
        xpReward: challenge.xpReward,
        targetValue: challenge.targetValue,
        currentValue: progress.currentValue,
        status: progress.status,
        startedAt: progress.startedAt.toISOString(),
        completedAt: progress.completedAt?.toISOString() ?? null,
        endsAt: challenge.endsAt?.toISOString() ?? null,
      });
    } else {
      // User hasn't started this challenge - auto-enroll them
      const [enrolled] = await db
        .insert(userChallenges)
        .values({
          userId,
          challengeId: challenge.id,
          currentValue: 0,
          status: "active",
        })
        .returning();

      result.push({
        id: challenge.id,
        title: challenge.title,
        description: challenge.description,
        type: challenge.type,
        xpReward: challenge.xpReward,
        targetValue: challenge.targetValue,
        currentValue: 0,
        status: "active",
        startedAt: enrolled.startedAt.toISOString(),
        completedAt: null,
        endsAt: challenge.endsAt?.toISOString() ?? null,
      });
    }
  }

  return result;
}

/**
 * Update challenge progress for a user based on metric
 */
export async function updateChallengeProgress(
  userId: string,
  metricKey: string,
  incrementBy = 1
): Promise<void> {
  const now = new Date();

  // Find active challenges matching this metric
  const matchingChallenges = await db
    .select({
      challenge: challenges,
      userChallenge: userChallenges,
    })
    .from(challenges)
    .innerJoin(userChallenges, eq(challenges.id, userChallenges.challengeId))
    .where(
      and(
        eq(challenges.metricKey, metricKey),
        eq(challenges.isActive, true),
        eq(userChallenges.userId, userId),
        eq(userChallenges.status, "active"),
        lte(challenges.startsAt, now),
        gte(challenges.endsAt, now)
      )
    );

  for (const { challenge, userChallenge } of matchingChallenges) {
    const newValue = userChallenge.currentValue + incrementBy;
    const isCompleted = newValue >= challenge.targetValue;

    // Update progress
    await db
      .update(userChallenges)
      .set({
        currentValue: newValue,
        status: isCompleted ? "completed" : "active",
        completedAt: isCompleted ? new Date() : null,
      })
      .where(eq(userChallenges.id, userChallenge.id));

    // Award XP if completed
    if (isCompleted) {
      await awardXp(userId, challenge.xpReward, `Completed challenge: ${challenge.title}`);

      // Send completion notification
      try {
        const io = getIO();
        emitNotification(io, userId, {
          id: Date.now(),
          type: "challenge",
          title: "Challenge Complete!",
          message: `You completed "${challenge.title}" and earned ${challenge.xpReward} XP!`,
          createdAt: new Date().toISOString(),
        });
      } catch {
        // Socket not available
      }
    }
  }
}

/**
 * Create default daily and weekly challenges
 */
export async function createDefaultChallenges(): Promise<void> {
  const now = new Date();
  const endOfDay = new Date(now);
  endOfDay.setHours(23, 59, 59, 999);

  const endOfWeek = new Date(now);
  endOfWeek.setDate(endOfWeek.getDate() + (7 - endOfWeek.getDay()));
  endOfWeek.setHours(23, 59, 59, 999);

  const defaultChallenges = [
    // Daily challenges
    {
      title: "Complete 2 Lessons",
      description: "Finish any 2 lessons today",
      type: "daily" as const,
      xpReward: 20,
      targetValue: 2,
      metricKey: "lessons_completed",
      startsAt: now,
      endsAt: endOfDay,
    },
    {
      title: "Study for 30 Minutes",
      description: "Accumulate 30 minutes of study time today",
      type: "daily" as const,
      xpReward: 15,
      targetValue: 30,
      metricKey: "study_minutes",
      startsAt: now,
      endsAt: endOfDay,
    },
    {
      title: "Pass a Quiz",
      description: "Score 70% or higher on any quiz",
      type: "daily" as const,
      xpReward: 25,
      targetValue: 1,
      metricKey: "quizzes_passed",
      startsAt: now,
      endsAt: endOfDay,
    },
    // Weekly challenges
    {
      title: "Study 5 Hours",
      description: "Accumulate 5 hours of study time this week",
      type: "weekly" as const,
      xpReward: 100,
      targetValue: 300,
      metricKey: "study_minutes",
      startsAt: now,
      endsAt: endOfWeek,
    },
    {
      title: "Complete 10 Lessons",
      description: "Finish 10 lessons this week",
      type: "weekly" as const,
      xpReward: 75,
      targetValue: 10,
      metricKey: "lessons_completed",
      startsAt: now,
      endsAt: endOfWeek,
    },
    {
      title: "Perfect Quiz Score",
      description: "Get 100% on any quiz",
      type: "special" as const,
      xpReward: 50,
      targetValue: 1,
      metricKey: "perfect_quiz",
      startsAt: now,
      endsAt: endOfWeek,
    },
  ];

  for (const challenge of defaultChallenges) {
    // Check if similar challenge already exists for this period
    const existing = await db
      .select()
      .from(challenges)
      .where(
        and(
          eq(challenges.title, challenge.title),
          eq(challenges.type, challenge.type),
          gte(challenges.endsAt, now)
        )
      )
      .limit(1);

    if (existing.length === 0) {
      await db.insert(challenges).values(challenge);
    }
  }
}

/**
 * Expire old challenges
 */
export async function expireOldChallenges(): Promise<void> {
  const now = new Date();

  // Mark challenges as expired
  await db
    .update(challenges)
    .set({ isActive: false })
    .where(lte(challenges.endsAt, now));

  // Mark user challenges as expired
  await db
    .update(userChallenges)
    .set({ status: "expired" })
    .where(
      and(
        eq(userChallenges.status, "active"),
        sql`${userChallenges.challengeId} IN (
          SELECT id FROM challenges WHERE ends_at <= ${now}
        )`
      )
    );
}
