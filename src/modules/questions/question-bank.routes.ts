import { Router } from "express";
import { requireAuth, requireRole } from "../../core/middleware/auth.js";
import { validateBody, validateQuery } from "../../core/middleware/validate.js";
import {
  questionBankListQuerySchema,
  questionBankCreateSchema,
  questionBankUpdateSchema,
  questionBankRandomQuerySchema,
  questionBankBulkImportSchema,
} from "../../shared/validators/index.js";
import {
  list,
  getById,
  create,
  update,
  remove,
  random,
  bulkImport,
  stats,
  review,
} from "./question-bank.controller.js";

const questionBankRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Question Bank
 *   description: Question bank management for assessments
 */

/**
 * @swagger
 * /api/question-bank:
 *   get:
 *     summary: List questions (Admin/Tutor)
 *     tags: [Question Bank]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: subjectId
 *         schema:
 *           type: integer
 *       - in: query
 *         name: topicId
 *         schema:
 *           type: integer
 *       - in: query
 *         name: difficulty
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of questions
 */
questionBankRoutes.get(
  "/",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  validateQuery(questionBankListQuerySchema),
  list
);

/**
 * @swagger
 * /api/question-bank/random:
 *   get:
 *     summary: Get random questions for assessment generation (Admin/Tutor)
 *     tags: [Question Bank]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Random questions
 */
questionBankRoutes.get(
  "/random",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  validateQuery(questionBankRandomQuerySchema),
  random
);

/**
 * @swagger
 * /api/question-bank/stats:
 *   get:
 *     summary: Get question bank statistics (Admin/Tutor)
 *     tags: [Question Bank]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Bank statistics
 */
questionBankRoutes.get(
  "/stats",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  stats
);

/**
 * @swagger
 * /api/question-bank/{id}:
 *   get:
 *     summary: Get a question by ID (Admin/Tutor)
 *     tags: [Question Bank]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Question details
 */
questionBankRoutes.get(
  "/:id",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  getById
);

/**
 * @swagger
 * /api/question-bank:
 *   post:
 *     summary: Create a new question (Admin/Tutor)
 *     tags: [Question Bank]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Question created
 */
questionBankRoutes.post(
  "/",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  validateBody(questionBankCreateSchema),
  create
);

/**
 * @swagger
 * /api/question-bank/bulk:
 *   post:
 *     summary: Bulk import questions (Admin only)
 *     tags: [Question Bank]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Questions imported
 */
questionBankRoutes.post(
  "/bulk",
  requireAuth,
  requireRole(["ADMIN"]),
  validateBody(questionBankBulkImportSchema),
  bulkImport
);

/**
 * @swagger
 * /api/question-bank/{id}:
 *   put:
 *     summary: Update a question (Admin/Tutor)
 *     tags: [Question Bank]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Question updated
 */
questionBankRoutes.put(
  "/:id",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  validateBody(questionBankUpdateSchema),
  update
);

/**
 * @swagger
 * /api/question-bank/{id}/review:
 *   post:
 *     summary: Mark question as reviewed (Admin/Tutor)
 *     tags: [Question Bank]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Question reviewed
 */
questionBankRoutes.post(
  "/:id/review",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  review
);

/**
 * @swagger
 * /api/question-bank/{id}:
 *   delete:
 *     summary: Delete a question (soft delete, Admin only)
 *     tags: [Question Bank]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Question deleted
 */
questionBankRoutes.delete(
  "/:id",
  requireAuth,
  requireRole(["ADMIN"]),
  remove
);

export { questionBankRoutes };
