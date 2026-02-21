import type { Request, Response } from "express";
import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { modules, subjects, userModuleSelections } from "../core/database/schema/index.js";
import { asyncHandler } from "../core/middleware/async-handler.js";

export const listUserModules = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const selections = await db
    .select({
      moduleId: modules.id,
      title: modules.title,
      grade: modules.grade,
      order: modules.order,
      subjectName: subjects.name,
    })
    .from(userModuleSelections)
    .innerJoin(modules, eq(userModuleSelections.moduleId, modules.id))
    .innerJoin(subjects, eq(modules.subjectId, subjects.id))
    .where(
      and(eq(userModuleSelections.userId, userId), eq(userModuleSelections.status, "unlocked"))
    )
    .orderBy(subjects.name, modules.grade, modules.order);

  res.json(selections);
});
