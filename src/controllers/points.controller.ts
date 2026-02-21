import type { Request, Response } from "express";
import { getUserPoints, getXpLeaderboard } from "../services/points.service.js";

export async function getPoints(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const points = await getUserPoints(userId);
    res.json(points);
  } catch (error) {
    console.error("[getPoints] Error:", error);
    res.status(500).json({ message: "Failed to get points" });
  }
}

export async function getLeaderboard(req: Request, res: Response) {
  try {
    const limit = Math.min(50, Number(req.query.limit) || 10);
    const leaderboard = await getXpLeaderboard(limit);
    res.json(leaderboard);
  } catch (error) {
    console.error("[getLeaderboard] Error:", error);
    res.status(500).json({ message: "Failed to get leaderboard" });
  }
}
