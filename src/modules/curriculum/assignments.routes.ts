import { Router } from "express";
import { requireAuth } from "../../core/middleware/auth.js";
import { onlyAdminOrTutor } from "../../core/guards/rbac.js";
import { validateQuery } from "../../core/middleware/validate.js";
import { assignmentQuerySchema } from "../../shared/validators/index.js";
import { list, getById, create, update } from "./assignments.controller.js";
import {
  getMySubmission,
  listSubmissions,
  submit,
  grade,
} from "./submissions.controller.js";

const assignmentsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Assignments
 *   description: Learning assignments management
 */

/**
 * @swagger
 * /api/assignments:
 *   get:
 *     summary: List assignments (optionally filtered by moduleId or grade)
 *     tags: [Assignments]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: moduleId
 *         schema:
 *           type: integer
 *       - in: query
 *         name: grade
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of assignments
 */
assignmentsRoutes.get(
  "/",
  requireAuth,
  validateQuery(assignmentQuerySchema),
  list
);

/**
 * @swagger
 * /api/assignments/{id}:
 *   get:
 *     summary: Get a single assignment by ID
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
 *     summary: Create a new assignment (Tutor/Admin)
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
assignmentsRoutes.post(
  "/",
  requireAuth,
  onlyAdminOrTutor,
  create
);

/**
 * @swagger
 * /api/assignments/{id}:
 *   patch:
 *     summary: Update an assignment (Tutor/Admin)
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
 *         description: Assignment updated
 *       404:
 *         description: Assignment not found
 */
assignmentsRoutes.patch(
  "/:id",
  requireAuth,
  onlyAdminOrTutor,
  update
);

/**
 * @swagger
 * /api/assignments/{id}/submission:
 *   get:
 *     summary: Get the current user's submission for an assignment
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
 *         description: Submission or null
 */
assignmentsRoutes.get("/:id/submission", requireAuth, getMySubmission);

/**
 * @swagger
 * /api/assignments/{id}/submissions:
 *   get:
 *     summary: List all submissions for an assignment (Tutor/Admin)
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
 *         description: List of submissions
 */
assignmentsRoutes.get("/:id/submissions", requireAuth, onlyAdminOrTutor, listSubmissions);

/**
 * @swagger
 * /api/assignments/{id}/submit:
 *   post:
 *     summary: Submit work for an assignment
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
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               submissionText:
 *                 type: string
 *     responses:
 *       201:
 *         description: Submission recorded
 */
assignmentsRoutes.post("/:id/submit", requireAuth, submit);

/**
 * @swagger
 * /api/assignments/{id}/grade:
 *   post:
 *     summary: Grade a submission using a rubric (Tutor/Admin)
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
 *             properties:
 *               rubricId:
 *                 type: integer
 *               rubricScores:
 *                 type: array
 *               totalScore:
 *                 type: integer
 *               maxScore:
 *                 type: integer
 *               feedback:
 *                 type: string
 *     responses:
 *       200:
 *         description: Submission graded
 *       404:
 *         description: No submission found
 */
assignmentsRoutes.post("/:id/grade", requireAuth, onlyAdminOrTutor, grade);

export { assignmentsRoutes };
