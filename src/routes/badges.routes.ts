import { Router } from "express";
import { list } from "../controllers/badges.controller.js";
import { requireAuth } from "../core/middleware/auth.js";

const badgesRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Badges
 *   description: Gamified achievements for learners
 */

/**
 * @swagger
 * /api/badges:
 *   get:
 *     summary: List badges earned by the current user
 *     tags: [Badges]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Badge collection
 */
badgesRoutes.get("/", requireAuth, list);

export { badgesRoutes };
