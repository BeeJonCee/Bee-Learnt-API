import { Router } from "express";
import { create, getById, list, listModules, update } from "./subjects.controller.js";
import { requireAuth, requireRole } from "../../core/middleware/auth.js";
import { validateBody } from "../../core/middleware/validate.js";
import { subjectCreateSchema } from "../../shared/validators/index.js";

const subjectsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Subjects
 *   description: Subject management
 */

/**
 * @swagger
 * /api/subjects:
 *   get:
 *     summary: List all subjects
 *     tags: [Subjects]
 *     responses:
 *       200:
 *         description: List of subjects
 */
subjectsRoutes.get("/", list);

/**
 * @swagger
 * /api/subjects/{id}:
 *   get:
 *     summary: Get a subject by ID
 *     tags: [Subjects]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Subject details
 */
subjectsRoutes.get("/:id", getById);

/**
 * @swagger
 * /api/subjects/{id}/modules:
 *   get:
 *     summary: List modules for a subject
 *     tags: [Subjects]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Subject modules
 */
subjectsRoutes.get("/:id/modules", listModules);

/**
 * @swagger
 * /api/subjects:
 *   post:
 *     summary: Create a subject (Admin only)
 *     tags: [Subjects]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Created
 */
subjectsRoutes.post("/", requireRole(["ADMIN", "TUTOR"]), validateBody(subjectCreateSchema), create);

/**
 * @swagger
 * /api/subjects/{id}:
 *   put:
 *     summary: Update a subject (Admin only)
 *     tags: [Subjects]
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
 *         description: Updated
 */
subjectsRoutes.put("/:id", requireRole(["ADMIN", "TUTOR"]), validateBody(subjectCreateSchema.partial()), update);

export { subjectsRoutes };
