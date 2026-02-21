import { Router } from "express";
import { listLearningPath, refreshLearningPath } from "../controllers/learning-path.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { learningPathRefreshSchema } from "../shared/validators/index.js";

const learningPathRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Learning Path
 *   description: Adaptive learning path recommendations
 */

/**
 * @swagger
 * /api/learning-path:
 *   get:
 *     summary: Retrieve the current learning path
 *     tags: [Learning Path]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Learning path sequence
 */
learningPathRoutes.get("/", requireAuth, listLearningPath);

/**
 * @swagger
 * /api/learning-path:
 *   post:
 *     summary: Refresh learning path recommendations
 *     tags: [Learning Path]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Updated learning path
 */
learningPathRoutes.post("/", requireAuth, validateBody(learningPathRefreshSchema), refreshLearningPath);

export { learningPathRoutes };
