import type { Request, Response } from "express";
import { db } from "../core/database/index.js";
import { quizAttempts, studySessions, users } from "../core/database/schema/index.js";
import { asyncHandler } from "../core/middleware/async-handler.js";

export const getLeaderboard = asyncHandler(async (_req: Request, res: Response) => {
  const [attemptRows, sessionRows, userRows] = await Promise.all([
    db.select().from(quizAttempts),
    db.select().from(studySessions),
    db.select({ id: users.id, name: users.name }).from(users),
  ]);

  const userMap = new Map(userRows.map((user) => [user.id, user.name]));
  const attemptsByUser = new Map<string, { total: number; count: number }>();

  attemptRows.forEach((attempt) => {
    const entry = attemptsByUser.get(attempt.userId) ?? { total: 0, count: 0 };
    const percentage = attempt.maxScore ? (attempt.score / attempt.maxScore) * 100 : 0;
    entry.total += percentage;
    entry.count += 1;
    attemptsByUser.set(attempt.userId, entry);
  });

  const minutesByUser = new Map<string, number>();
  sessionRows.forEach((session) => {
    const total = minutesByUser.get(session.userId) ?? 0;
    minutesByUser.set(session.userId, total + session.durationMinutes);
  });

  const leaderboard = Array.from(userMap.entries()).map(([userId, name]) => {
    const attemptStats = attemptsByUser.get(userId);
    const averageScore = attemptStats && attemptStats.count > 0
      ? Math.round(attemptStats.total / attemptStats.count)
      : 0;
    const minutes = minutesByUser.get(userId) ?? 0;
    const score = Math.round(averageScore + Math.min(minutes / 30, 20));
    return { userId, name, averageScore, minutes, score };
  });

  leaderboard.sort((a, b) => b.score - a.score);

  res.json(leaderboard.slice(0, 10));
});
