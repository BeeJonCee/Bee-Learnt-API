import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber } from "../shared/utils/parse.js";
import { createEvent, listEvents } from "../services/events.service.js";

const parseDate = (value?: string | string[]) => {
  if (!value || Array.isArray(value)) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

export const list = asyncHandler(async (req: Request, res: Response) => {
  const role = req.user?.role ?? "STUDENT";
  const limit = parseNumber(req.query.limit as string | undefined) ?? 6;
  const from = parseDate(req.query.from as string | undefined);
  const to = parseDate(req.query.to as string | undefined);

  if ((req.query.from && !from) || (req.query.to && !to)) {
    res.status(400).json({ message: "Invalid date filter" });
    return;
  }

  const data = await listEvents({ role, limit, from, to });
  res.json(data);
});

export const create = asyncHandler(async (req: Request, res: Response) => {
  const created = await createEvent(req.body);
  res.status(201).json(created);
});
