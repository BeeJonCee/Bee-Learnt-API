import type { Request, Response } from "express";
import { getUserChallenges, createDefaultChallenges } from "../services/challenges.service.js";

export async function getChallenges(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const challenges = await getUserChallenges(userId);
    res.json(challenges);
  } catch (error) {
    console.error("[getChallenges] Error:", error);
    res.status(500).json({ message: "Failed to get challenges" });
  }
}

export async function initializeChallenges(req: Request, res: Response) {
  try {
    // Admin only endpoint to create default challenges
    if (req.user?.role !== "ADMIN") {
      res.status(403).json({ message: "Forbidden" });
      return;
    }

    await createDefaultChallenges();
    res.json({ message: "Default challenges created" });
  } catch (error) {
    console.error("[initializeChallenges] Error:", error);
    res.status(500).json({ message: "Failed to initialize challenges" });
  }
}
