import { Router } from "express";
import { requireAuth, requireRole } from "../../core/middleware/auth.js";
import { validateBody, validateQuery } from "../../core/middleware/validate.js";
import { assessmentCreateSchema, assessmentListQuerySchema } from "../../shared/validators/index.js";
import { create, getById, list, publish, start } from "./assessments.controller.js";

const assessmentsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Assessments
 *   description: Assessment creation, publishing, and student attempts
 */

/**
 * @swagger
 * /api/assessments:
 *   get:
 *     summary: List assessments
 *     tags: [Assessments]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: subjectId
 *         schema:
 *           type: integer
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of assessments
 */
assessmentsRoutes.get("/", requireAuth, validateQuery(assessmentListQuerySchema), list);

/**
 * @swagger
 * /api/assessments/{id}:
 *   get:
 *     summary: Get assessment by ID
 *     tags: [Assessments]
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
 *         description: Assessment details
 */
assessmentsRoutes.get("/:id", requireAuth, getById);

/**
 * @swagger
 * /api/assessments:
 *   post:
 *     summary: Create an assessment (Admin/Tutor)
 *     tags: [Assessments]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Assessment created
 */
assessmentsRoutes.post(
  "/",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  validateBody(assessmentCreateSchema),
  create
);

/**
 * @swagger
 * /api/assessments/{id}/publish:
 *   post:
 *     summary: Publish an assessment (Admin/Tutor)
 *     tags: [Assessments]
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
 *         description: Assessment published
 */
assessmentsRoutes.post(
  "/:id/publish",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  publish
);

/**
 * @swagger
 * /api/assessments/{id}/start:
 *   post:
 *     summary: Start an assessment attempt (Student/Admin)
 *     tags: [Assessments]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       201:
 *         description: Attempt started
 */
assessmentsRoutes.post(
  "/:id/start",
  requireAuth,
  requireRole(["STUDENT", "ADMIN"]),
  start
);

export { assessmentsRoutes };
