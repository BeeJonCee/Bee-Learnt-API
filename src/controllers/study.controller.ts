import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { createSession, getStudySummary, listSessions } from "../services/study.service.js";

export const list = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  const data = await listSessions(userId);
  res.json(data);
});

export const create = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  const created = await createSession(userId, req.body);
  res.status(201).json(created);
});

export const summary = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  const data = await getStudySummary(userId);
  res.json(data);
});
