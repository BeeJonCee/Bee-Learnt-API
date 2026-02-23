import { Router } from "express";
import { requireAuth } from "../../core/middleware/auth.js";
import { validateBody } from "../../core/middleware/validate.js";
import { attemptAnswerSchema } from "../../shared/validators/index.js";
import { answer, getById, review, submit } from "./attempts.controller.js";

const attemptsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Attempts
 *   description: Assessment attempt flow (answer, submit, review)
 */

/**
 * @swagger
 * /api/attempts/{attemptId}:
 *   get:
 *     summary: Get an attempt by ID
 *     tags: [Attempts]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: attemptId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Attempt details
 */
attemptsRoutes.get("/:attemptId", requireAuth, getById);

/**
 * @swagger
 * /api/attempts/{attemptId}/answer:
 *   put:
 *     summary: Submit an answer for a question in an attempt
 *     tags: [Attempts]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: attemptId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Answer recorded
 */
attemptsRoutes.put("/:attemptId/answer", requireAuth, validateBody(attemptAnswerSchema), answer);

/**
 * @swagger
 * /api/attempts/{attemptId}/submit:
 *   post:
 *     summary: Submit an attempt for grading
 *     tags: [Attempts]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: attemptId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Attempt submitted and graded
 */
attemptsRoutes.post("/:attemptId/submit", requireAuth, submit);

/**
 * @swagger
 * /api/attempts/{attemptId}/review:
 *   get:
 *     summary: Review a completed attempt
 *     tags: [Attempts]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: attemptId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Attempt review with answers and grades
 */
attemptsRoutes.get("/:attemptId/review", requireAuth, review);

export { attemptsRoutes };
