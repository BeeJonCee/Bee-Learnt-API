import { Router } from "express";
import { create, list, summary } from "../controllers/study.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { studySessionCreateSchema } from "../shared/validators/index.js";

const studyRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Study
 *   description: Study session tracking
 */

/**
 * @swagger
 * /api/study/sessions:
 *   get:
 *     summary: List study sessions for the current user
 *     tags: [Study]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Study sessions list
 */
studyRoutes.get("/sessions", requireAuth, list);

/**
 * @swagger
 * /api/study/sessions:
 *   post:
 *     summary: Create a new study session
 *     tags: [Study]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Study session created
 */
studyRoutes.post("/sessions", requireAuth, validateBody(studySessionCreateSchema), create);

/**
 * @swagger
 * /api/study/summary:
 *   get:
 *     summary: Get study summary for the current user
 *     tags: [Study]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Study summary
 */
studyRoutes.get("/summary", requireAuth, summary);

export { studyRoutes };
