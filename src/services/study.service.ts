import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { badges, streaks, studySessions, userBadges } from "../core/database/schema/index.js";

type StudySessionCreateInput = {
  startedAt: string;
  endedAt?: string;
  durationMinutes: number;
};

function toDayKey(date: Date) {
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

function getWeekStart(date: Date) {
  const day = date.getUTCDay();
  const diff = (day + 6) % 7;
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate() - diff));
}

export async function listSessions(userId: string) {
  return db.select().from(studySessions).where(eq(studySessions.userId, userId));
}

export async function createSession(userId: string, payload: StudySessionCreateInput) {
  const [created] = await db
    .insert(studySessions)
    .values({
      userId,
      startedAt: new Date(payload.startedAt),
      endedAt: payload.endedAt ? new Date(payload.endedAt) : null,
      durationMinutes: payload.durationMinutes,
    })
    .returning();

  const sessionDate = new Date(payload.endedAt ?? payload.startedAt);
  const [existingStreak] = await db.select().from(streaks).where(eq(streaks.userId, userId));

  const sessionDayKey = toDayKey(sessionDate);
  const weekStart = getWeekStart(sessionDate);
  let currentStreak = 1;
  let longestStreak = 1;
  let weeklyMinutes = payload.durationMinutes;

  if (existingStreak) {
    const lastStudyDate = existingStreak.lastStudyDate
      ? new Date(existingStreak.lastStudyDate)
      : null;

    if (lastStudyDate) {
      const lastDayKey = toDayKey(lastStudyDate);
      const diffDays = Math.round((sessionDayKey - lastDayKey) / 86_400_000);

      if (diffDays === 0) {
        currentStreak = existingStreak.currentStreak;
      } else if (diffDays === 1) {
        currentStreak = existingStreak.currentStreak + 1;
      } else {
        currentStreak = 1;
      }

      const lastWeekStart = getWeekStart(lastStudyDate);
      const isSameWeek = lastWeekStart.getTime() === weekStart.getTime();
      weeklyMinutes = isSameWeek
        ? existingStreak.weeklyMinutes + payload.durationMinutes
        : payload.durationMinutes;

      longestStreak = Math.max(existingStreak.longestStreak, currentStreak);
    }
  }

  if (existingStreak) {
    await db
      .update(streaks)
      .set({
        currentStreak,
        longestStreak,
        lastStudyDate: sessionDate,
        weeklyMinutes,
        updatedAt: new Date(),
      })
      .where(eq(streaks.id, existingStreak.id));
  } else {
    await db.insert(streaks).values({
      userId,
      currentStreak,
      longestStreak,
      lastStudyDate: sessionDate,
      weeklyMinutes,
      updatedAt: new Date(),
    });
  }

  const streakBadges = await db
    .select()
    .from(badges)
    .where(eq(badges.ruleKey, "lesson_streak"));

  for (const badge of streakBadges) {
    const criteria = badge.criteria as { streak?: number };
    const requiredStreak = criteria.streak ?? 3;

    if (currentStreak >= requiredStreak) {
      const [existingBadge] = await db
        .select()
        .from(userBadges)
        .where(and(eq(userBadges.userId, userId), eq(userBadges.badgeId, badge.id)));

      if (!existingBadge) {
        await db.insert(userBadges).values({
          userId,
          badgeId: badge.id,
          awardedAt: new Date(),
        });
      }
    }
  }

  return created;
}

export async function getStudySummary(userId: string) {
  const [streak] = await db.select().from(streaks).where(eq(streaks.userId, userId));
  const sessions = await db
    .select({ durationMinutes: studySessions.durationMinutes })
    .from(studySessions)
    .where(eq(studySessions.userId, userId));

  const totalMinutes = sessions.reduce(
    (total, session) => total + (session.durationMinutes ?? 0),
    0
  );

  return {
    streak: streak ?? {
      currentStreak: 0,
      longestStreak: 0,
      weeklyMinutes: 0,
      lastStudyDate: null,
    },
    totalMinutes,
  };
}
