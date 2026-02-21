import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber } from "../shared/utils/parse.js";
import { createAnnouncement, listAnnouncements } from "../services/announcements.service.js";

export const list = asyncHandler(async (req: Request, res: Response) => {
  const role = req.user?.role ?? "STUDENT";
  const limit = parseNumber(req.query.limit as string | undefined) ?? 5;
  const data = await listAnnouncements(role, limit);
  res.json(data);
});

export const create = asyncHandler(async (req: Request, res: Response) => {
  const created = await createAnnouncement(req.body);
  res.status(201).json(created);
});
