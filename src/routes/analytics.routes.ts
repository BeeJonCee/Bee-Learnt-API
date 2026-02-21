import { Router } from "express";
import { requireAuth, requireRole } from "../core/middleware/auth.js";
import {
  platformStatsHandler,
  subjectAnalyticsHandler,
  topicMasteryHeatmapHandler,
  studentAnalyticsHandler,
  weakTopicsHandler,
  assessmentAnalyticsHandler,
} from "../controllers/analytics.controller.js";

const analyticsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Analytics
 *   description: Platform and student analytics
 */

analyticsRoutes.use(requireAuth);

/**
 * @swagger
 * /api/analytics/platform:
 *   get:
 *     summary: Platform-wide statistics
 *     tags: [Analytics]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Platform statistics
 *       403:
 *         description: Admin only
 */
analyticsRoutes.get(
  "/platform",
  requireRole(["ADMIN"]),
  platformStatsHandler
);

/**
 * @swagger
 * /api/analytics/topic-mastery:
 *   get:
 *     summary: Topic mastery heatmap across students
 *     tags: [Analytics]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Heatmap data
 */
analyticsRoutes.get(
  "/topic-mastery",
  requireRole(["ADMIN", "TUTOR"]),
  topicMasteryHeatmapHandler
);

/**
 * @swagger
 * /api/analytics/subject/{subjectId}:
 *   get:
 *     summary: Subject performance breakdown
 *     tags: [Analytics]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: subjectId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Subject analytics
 */
analyticsRoutes.get(
  "/subject/:subjectId",
  requireRole(["ADMIN", "TUTOR"]),
  subjectAnalyticsHandler
);

/**
 * @swagger
 * /api/analytics/assessment/{assessmentId}:
 *   get:
 *     summary: Assessment results distribution
 *     tags: [Analytics]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: assessmentId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Assessment analytics
 */
analyticsRoutes.get(
  "/assessment/:assessmentId",
  requireRole(["ADMIN", "TUTOR"]),
  assessmentAnalyticsHandler
);

/**
 * @swagger
 * /api/analytics/student/{userId}:
 *   get:
 *     summary: Individual student analytics
 *     tags: [Analytics]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Student analytics
 */
analyticsRoutes.get(
  "/student/:userId",
  requireRole(["ADMIN", "TUTOR", "PARENT"]),
  studentAnalyticsHandler
);

/**
 * @swagger
 * /api/analytics/weak-topics:
 *   get:
 *     summary: Current user's weakest topics
 *     tags: [Analytics]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Weak topics list
 */
analyticsRoutes.get("/weak-topics", weakTopicsHandler);

export { analyticsRoutes };
