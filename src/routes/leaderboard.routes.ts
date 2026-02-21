import { Router } from "express";
import { getLeaderboard } from "../controllers/leaderboard.controller.js";
import { requireAuth } from "../core/middleware/auth.js";

const leaderboardRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Leaderboard
 *   description: Gamified leaderboards and rankings
 */

/**
 * @swagger
 * /api/leaderboard:
 *   get:
 *     summary: Retrieve leaderboard standings
 *     tags: [Leaderboard]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Leaderboard entries
 */
leaderboardRoutes.get("/", requireAuth, getLeaderboard);

export { leaderboardRoutes };
