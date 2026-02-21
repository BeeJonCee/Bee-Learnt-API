import { Router } from "express";
import { tutor } from "../controllers/ai.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { aiTutorSchema } from "../shared/validators/index.js";

const aiRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: AI
 *   description: AI-powered tutoring assistance
 */

/**
 * @swagger
 * /api/ai/tutor:
 *   post:
 *     summary: Generate AI tutoring guidance for a learner
 *     tags: [AI]
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
 *         description: AI tutor response payload
 */
aiRoutes.post("/tutor", requireAuth, validateBody(aiTutorSchema), tutor);

export { aiRoutes };
