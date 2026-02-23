import { Router } from "express";
import {
  check,
  generate,
  getById,
  getReviewById,
  list,
  listQuestions,
  submit,
  update,
} from "./quizzes.controller.js";
import { requireAuth } from "../../core/middleware/auth.js";
import { validateBody } from "../../core/middleware/validate.js";
import { quizGenerateSchema, quizSubmitSchema } from "../../shared/validators/index.js";
import { requirePermission, onlyAdminOrTutor } from "../../core/guards/rbac.js";

const quizzesRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Quizzes
 *   description: Quiz discovery, attempts, and creation
 */

// ========== PUBLIC ROUTES ==========
// Browse quizzes (anyone can view quiz list)
/**
 * @swagger
 * /api/quizzes:
 *   get:
 *     summary: Browse available quizzes
 *     tags: [Quizzes]
 *     responses:
 *       200:
 *         description: Quiz catalogue
 */
quizzesRoutes.get("/", list);

// ========== AUTHENTICATED ROUTES ==========
// View specific quiz and questions (all authenticated users)
/**
 * @swagger
 * /api/quizzes/{id}:
 *   get:
 *     summary: Retrieve quiz details
 *     tags: [Quizzes]
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
 *         description: Quiz details
 */
quizzesRoutes.get("/:id", requireAuth, getById);

/**
 * @swagger
 * /api/quizzes/{id}/review:
 *   get:
 *     summary: Retrieve quiz details including answer keys (Admin/Tutor)
 *     tags: [Quizzes]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Quiz review payload
 */
quizzesRoutes.get("/:id/review", requireAuth, onlyAdminOrTutor, getReviewById);

/**
 * @swagger
 * /api/quizzes/{id}/questions:
 *   get:
 *     summary: Retrieve quiz questions
 *     tags: [Quizzes]
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
 *         description: Quiz question set
 */
quizzesRoutes.get("/:id/questions", requireAuth, listQuestions);

// ========== STUDENT ROUTES ==========
// Take/submit quizzes (students, tutors, admins can attempt quizzes)
/**
 * @swagger
 * /api/quizzes/check:
 *   post:
 *     summary: Validate quiz attempt before submission
 *     tags: [Quizzes]
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
 *         description: Attempt validation result
 */
quizzesRoutes.post("/check", requireAuth, requirePermission("quiz:take"), check);
/**
 * @swagger
 * /api/quizzes/submit:
 *   post:
 *     summary: Submit quiz responses
 *     tags: [Quizzes]
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
 *         description: Quiz submission outcome
 */
quizzesRoutes.post("/submit", requireAuth, requirePermission("quiz:take"), validateBody(quizSubmitSchema), submit);

// ========== ADMIN/TUTOR ONLY ROUTES ==========
// Generate/create quizzes (only admin and tutor can create quizzes)
/**
 * @swagger
 * /api/quizzes/generate:
 *   post:
 *     summary: Generate a quiz blueprint
 *     tags: [Quizzes]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       201:
 *         description: Quiz generated
 */
quizzesRoutes.post("/generate", requireAuth, onlyAdminOrTutor, validateBody(quizGenerateSchema), generate);
quizzesRoutes.put("/:id", requireAuth, onlyAdminOrTutor, update);

export { quizzesRoutes };
