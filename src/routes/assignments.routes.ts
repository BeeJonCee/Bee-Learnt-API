import { Router } from "express";
import { create, getById, list, update } from "../controllers/assignments.controller.js";
import { requireAuth, requireRole } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { assignmentCreateSchema, assignmentUpdateSchema } from "../shared/validators/index.js";

const assignmentsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Assignments
 *   description: Manage module assignments across learners
 */

/**
 * @swagger
 * /api/assignments:
 *   get:
 *     summary: List assignments for the current user context
 *     tags: [Assignments]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Collection of assignments
 */
assignmentsRoutes.get("/", requireAuth, list);

/**
 * @swagger
 * /api/assignments/{id}:
 *   get:
 *     summary: Fetch a specific assignment by ID
 *     tags: [Assignments]
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
 *         description: Assignment details
 *       404:
 *         description: Assignment not found
 */
assignmentsRoutes.get("/:id", requireAuth, getById);

/**
 * @swagger
 * /api/assignments:
 *   post:
 *     summary: Create a new assignment
 *     tags: [Assignments]
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
 *         description: Assignment created
 */
assignmentsRoutes.post("/", requireRole(["ADMIN"]), validateBody(assignmentCreateSchema), create);

/**
 * @swagger
 * /api/assignments/{id}:
 *   patch:
 *     summary: Update assignment progress or metadata
 *     tags: [Assignments]
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
 *             type: object
 *     responses:
 *       200:
 *         description: Assignment updated
 */
assignmentsRoutes.patch("/:id", requireAuth, validateBody(assignmentUpdateSchema), update);

export { assignmentsRoutes };
