import { Router } from "express";
import { requireAuth } from "../core/middleware/auth.js";
import { getPoints, getLeaderboard } from "../controllers/points.controller.js";

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Points
 *   description: Experience points and rewards
 */

// All routes require authentication
router.use(requireAuth);

/**
 * @swagger
 * /api/points:
 *   get:
 *     summary: Retrieve the current user's point balance
 *     tags: [Points]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Point balance information
 */
router.get("/", getPoints);

/**
 * @swagger
 * /api/points/leaderboard:
 *   get:
 *     summary: Global points leaderboard
 *     tags: [Points]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Points leaderboard entries
 */
router.get("/leaderboard", getLeaderboard);

export { router as pointsRoutes };
