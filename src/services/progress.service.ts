import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { modules, progressTracking, quizAttempts } from "../core/database/schema/index.js";

type ProgressQuery = {
  lessonId?: number;
  moduleId?: number;
};

type ProgressUpdate = {
  lessonId?: number;
  moduleId?: number;
  completed?: boolean;
  timeSpentMinutes?: number;
};

export async function listProgress(userId: string, query: ProgressQuery) {
  const conditions = [eq(progressTracking.userId, userId)];
  if (query.lessonId) conditions.push(eq(progressTracking.lessonId, query.lessonId));
  if (query.moduleId) conditions.push(eq(progressTracking.moduleId, query.moduleId));

  return db
    .select()
    .from(progressTracking)
    .where(and(...conditions));
}

export async function upsertProgress(userId: string, payload: ProgressUpdate) {
  const { lessonId, moduleId, completed, timeSpentMinutes } = payload;
  const criteria = lessonId
    ? eq(progressTracking.lessonId, lessonId)
    : eq(progressTracking.moduleId, moduleId as number);

  const [existing] = await db
    .select()
    .from(progressTracking)
    .where(and(eq(progressTracking.userId, userId), criteria));

  if (existing) {
    const nextTime =
      typeof timeSpentMinutes === "number"
        ? existing.timeSpentMinutes + timeSpentMinutes
        : existing.timeSpentMinutes;

    const [updated] = await db
      .update(progressTracking)
      .set({
        completed: typeof completed === "boolean" ? completed : existing.completed,
        timeSpentMinutes: nextTime,
        lastAccessedAt: new Date(),
        updatedAt: new Date(),
      })
      .where(eq(progressTracking.id, existing.id))
      .returning();

    return { record: updated, created: false };
  }

  const [created] = await db
    .insert(progressTracking)
    .values({
      userId,
      lessonId: lessonId ?? null,
      moduleId: moduleId ?? null,
      completed: completed ?? false,
      timeSpentMinutes: timeSpentMinutes ?? 0,
      lastAccessedAt: new Date(),
      updatedAt: new Date(),
    })
    .returning();

  return { record: created, created: true };
}

export async function getProgressSummary(userId: string) {
  const progress = await db
    .select({
      moduleId: progressTracking.moduleId,
      lessonId: progressTracking.lessonId,
      completed: progressTracking.completed,
      timeSpentMinutes: progressTracking.timeSpentMinutes,
    })
    .from(progressTracking)
    .where(eq(progressTracking.userId, userId));

  const attempts = await db
    .select({ score: quizAttempts.score, maxScore: quizAttempts.maxScore })
    .from(quizAttempts)
    .where(eq(quizAttempts.userId, userId));

  const moduleRows = await db.select().from(modules);
  const moduleProgress = moduleRows.map((moduleRow) => {
    const moduleLessons = progress.filter((entry) => entry.moduleId === moduleRow.id);
    const completedLessons = moduleLessons.filter((entry) => entry.completed).length;
    const totalLessons = moduleLessons.length;
    const completion = totalLessons === 0 ? 0 : Math.round((completedLessons / totalLessons) * 100);

    return {
      moduleId: moduleRow.id,
      title: moduleRow.title,
      grade: moduleRow.grade,
      completion,
    };
  });

  const averageScore = attempts.length
    ? Math.round(
        attempts.reduce(
          (total, attempt) => total + (attempt.score / attempt.maxScore) * 100,
          0
        ) / attempts.length
      )
    : 0;

  return {
    lessonCompletions: progress.filter((entry) => entry.completed).length,
    timeSpentMinutes: progress.reduce((total, entry) => total + entry.timeSpentMinutes, 0),
    averageScore,
    moduleProgress,
  };
}
