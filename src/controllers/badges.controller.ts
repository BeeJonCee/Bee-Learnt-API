import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { listBadgesForUser } from "../services/badges.service.js";

export const list = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const badges = await listBadgesForUser(userId);
  res.json({ badges });
});
