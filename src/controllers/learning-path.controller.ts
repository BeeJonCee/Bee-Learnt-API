import type { Request, Response } from "express";
import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import {
  learningPathItems,
  learningProfiles,
  modules,
  progressTracking,
} from "../core/database/schema/index.js";
import { asyncHandler } from "../core/middleware/async-handler.js";

async function generatePath(userId: string) {
  const progress = await db
    .select({ moduleId: progressTracking.moduleId, completed: progressTracking.completed })
    .from(progressTracking)
    .where(eq(progressTracking.userId, userId));

  const moduleRows = await db.select().from(modules);
  const completionByModule = new Map<number, number>();

  moduleRows.forEach((module) => {
    const moduleEntries = progress.filter((entry) => entry.moduleId === module.id);
    const completed = moduleEntries.filter((entry) => entry.completed).length;
    const total = moduleEntries.length;
    const completion = total === 0 ? 0 : Math.round((completed / total) * 100);
    completionByModule.set(module.id, completion);
  });

  const nextModules = moduleRows
    .map((module) => ({ module, completion: completionByModule.get(module.id) ?? 0 }))
    .sort((a, b) => a.completion - b.completion)
    .slice(0, 3);

  if (nextModules.length === 0) return [];

  const inserts = nextModules.map((entry, index) => ({
    userId,
    moduleId: entry.module.id,
    title: `${entry.module.title} (Grade ${entry.module.grade})`,
    reason:
      entry.completion === 0
        ? "Start your first lesson to build momentum."
        : `Complete the next lessons to reach ${Math.min(entry.completion + 20, 100)}%`,
    priority: index + 1,
    status: "active" as const,
  }));

  return db.insert(learningPathItems).values(inserts).returning();
}

export const listLearningPath = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const existing = await db
    .select()
    .from(learningPathItems)
    .where(and(eq(learningPathItems.userId, userId), eq(learningPathItems.status, "active")))
    .orderBy(learningPathItems.priority);

  if (existing.length > 0) {
    res.json(existing);
    return;
  }

  const created = await generatePath(userId);
  res.json(created);
});

export const refreshLearningPath = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  await db
    .update(learningPathItems)
    .set({ status: "dismissed" })
    .where(eq(learningPathItems.userId, userId));

  const { goal, focusTags } = req.body as { goal?: string; focusTags?: string[] };
  if (goal || focusTags) {
    const [existingProfile] = await db
      .select()
      .from(learningProfiles)
      .where(eq(learningProfiles.userId, userId));

    if (existingProfile) {
      await db
        .update(learningProfiles)
        .set({
          goals: goal ? [goal] : existingProfile.goals,
          updatedAt: new Date(),
        })
        .where(eq(learningProfiles.userId, userId));
    } else {
      await db.insert(learningProfiles).values({
        userId,
        goals: goal ? [goal] : [],
        updatedAt: new Date(),
      });
    }
  }

  const created = await generatePath(userId);
  res.status(201).json(created);
});
