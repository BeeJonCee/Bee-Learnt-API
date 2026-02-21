import type { Request, Response } from "express";
import { z } from "zod";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { listChecklistItems, upsertChecklistProgress } from "../services/checklists.service.js";

const moduleQuerySchema = z.object({
  moduleId: z.number().int().positive(),
});

export const list = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const parsed = moduleQuerySchema.safeParse({
    moduleId: req.query.moduleId ? Number(req.query.moduleId) : undefined,
  });
  if (!parsed.success) {
    res.status(400).json({ message: "moduleId is required", issues: parsed.error.issues });
    return;
  }

  const data = await listChecklistItems(parsed.data.moduleId, userId);
  res.json(data);
});

export const update = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const { itemId, completed } = req.body as { itemId: number; completed: boolean };
  const result = await upsertChecklistProgress(userId, itemId, completed);
  res.status(result.created ? 201 : 200).json(result.record);
});
