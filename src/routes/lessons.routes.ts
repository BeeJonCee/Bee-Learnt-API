import { Router } from "express";
import { create, getById, list, update } from "../controllers/lessons.controller.js";
import { requireAuth, requireRole } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { lessonCreateSchema, lessonUpdateSchema } from "../shared/validators/index.js";

const lessonsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Lessons
 *   description: Lesson catalogue and delivery endpoints
 */

// Public route - allow browsing lessons

/**
 * @swagger
 * /api/lessons:
 *   get:
 *     summary: List lessons with pagination and filters
 *     tags: [Lessons]
 *     responses:
 *       200:
 *         description: Array of lessons
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Lesson'
 */
lessonsRoutes.get("/", list);

// Authenticated routes - viewing lesson content requires login for progress tracking

/**
 * @swagger
 * /api/lessons/{id}:
 *   get:
 *     summary: Fetch lesson details and learning content
 *     tags: [Lessons]
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
 *         description: Lesson details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Lesson'
 *       401:
 *         description: Authentication required
 */
lessonsRoutes.get("/:id", requireAuth, getById);

// Admin routes

/**
 * @swagger
 * /api/lessons:
 *   post:
 *     summary: Create a lesson within a module
 *     tags: [Lessons]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LessonCreateRequest'
 *     responses:
 *       201:
 *         description: Lesson created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Lesson'
 */
lessonsRoutes.post("/", requireRole(["ADMIN", "TUTOR"]), validateBody(lessonCreateSchema), create);

/**
 * @swagger
 * /api/lessons/{id}:
 *   put:
 *     summary: Update lesson metadata or content
 *     tags: [Lessons]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LessonUpdateRequest'
 *     responses:
 *       200:
 *         description: Updated lesson details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Lesson'
 */
lessonsRoutes.put("/:id", requireRole(["ADMIN", "TUTOR"]), validateBody(lessonUpdateSchema), update);

export { lessonsRoutes };
