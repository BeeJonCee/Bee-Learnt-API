import { Router } from "express";
import { getParentOverview, getParentInsightsHandler } from "../controllers/parent.controller.js";
import { requireRole } from "../core/middleware/auth.js";

const parentRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Parent
 *   description: Parent dashboards and insights
 */

/**
 * @swagger
 * /api/parent/overview:
 *   get:
 *     summary: Parent overview dashboard metrics
 *     tags: [Parent]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Parent overview data
 */
parentRoutes.get("/overview", requireRole(["PARENT"]), getParentOverview);

/**
 * @swagger
 * /api/parent/insights:
 *   get:
 *     summary: Insight feed for parents
 *     tags: [Parent]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Parent insights payload
 */
parentRoutes.get("/insights", requireRole(["PARENT"]), getParentInsightsHandler);

export { parentRoutes };
