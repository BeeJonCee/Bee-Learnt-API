import { Router } from "express";
import { requireAuth } from "../../core/middleware/auth.js";
import { onlyAdminOrTutor } from "../../core/guards/rbac.js";
import { list, getById, create, update } from "./rubrics.controller.js";

const rubricsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Rubrics
 *   description: Grading rubrics management
 */

/**
 * @swagger
 * /api/rubrics:
 *   get:
 *     summary: List rubrics (optionally filtered by subjectId)
 *     tags: [Rubrics]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: subjectId
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of rubrics
 */
rubricsRoutes.get("/", requireAuth, list);

/**
 * @swagger
 * /api/rubrics/{id}:
 *   get:
 *     summary: Get a rubric by ID
 *     tags: [Rubrics]
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
 *         description: Rubric details
 *       404:
 *         description: Not found
 */
rubricsRoutes.get("/:id", requireAuth, getById);

/**
 * @swagger
 * /api/rubrics:
 *   post:
 *     summary: Create a rubric (Tutor/Admin)
 *     tags: [Rubrics]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [title, criteria]
 *             properties:
 *               title:
 *                 type: string
 *               subjectId:
 *                 type: integer
 *               criteria:
 *                 type: array
 *     responses:
 *       201:
 *         description: Rubric created
 */
rubricsRoutes.post("/", requireAuth, onlyAdminOrTutor, create);

/**
 * @swagger
 * /api/rubrics/{id}:
 *   patch:
 *     summary: Update a rubric (Tutor/Admin)
 *     tags: [Rubrics]
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
 *         description: Rubric updated
 *       404:
 *         description: Not found
 */
rubricsRoutes.patch("/:id", requireAuth, onlyAdminOrTutor, update);

export { rubricsRoutes };
