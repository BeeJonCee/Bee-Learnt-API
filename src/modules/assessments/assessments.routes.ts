import { Router } from "express";
import { requireAuth, requireRole } from "../../core/middleware/auth.js";
import { validateQuery } from "../../core/middleware/validate.js";
import { assessmentListQuerySchema } from "../../shared/validators/index.js";
import {
  addQuestion,
  assign,
  close,
  create,
  createSection,
  deleteAssignment,
  deleteAssessmentHandler,
  deleteSectionHandler,
  debugQuestionOptions,
  finalizeMarkingHandler,
  getAssignments,
  getById,
  getLatestReleasedAttempt,
  getPaperResultHandler,
  getSubmissionById,
  getSubmissions,
  getWorkflow,
  list,
  listMine,
  markAnswerHandler,
  patchQuestion,
  publish,
  release,
  removeQuestion,
  startMarking,
  start,
  updateAssessmentHandler,
  updateAssignmentHandler,
  updateSectionHandler,
} from "./assessments.controller.js";

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
assessmentsRoutes.get(
  "/my-assessments",
  requireAuth,
  requireRole(["STUDENT"]),
  listMine
);
// Legacy alias for compatibility with paper list naming.
assessmentsRoutes.get(
  "/my-papers",
  requireAuth,
  requireRole(["STUDENT"]),
  listMine
);

assessmentsRoutes.get(
  "/questions/:assessmentQuestionId/options-debug",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  debugQuestionOptions
);

// Paper workflow endpoints under assessments.
assessmentsRoutes.post(
  "/:id/publish",
  requireAuth,
  requireRole(["ADMIN"]),
  publish
);
assessmentsRoutes.post(
  "/:id/close",
  requireAuth,
  requireRole(["ADMIN"]),
  close
);
assessmentsRoutes.post(
  "/:id/start-marking",
  requireAuth,
  requireRole(["ADMIN"]),
  startMarking
);
assessmentsRoutes.post(
  "/:id/release",
  requireAuth,
  requireRole(["ADMIN"]),
  release
);

assessmentsRoutes.get(
  "/:id/workflow",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  getWorkflow
);

assessmentsRoutes.post(
  "/:id/sections",
  requireAuth,
  requireRole(["ADMIN"]),
  createSection
);
assessmentsRoutes.put(
  "/:id/sections/:sectionId",
  requireAuth,
  requireRole(["ADMIN"]),
  updateSectionHandler
);
assessmentsRoutes.delete(
  "/:id/sections/:sectionId",
  requireAuth,
  requireRole(["ADMIN"]),
  deleteSectionHandler
);

assessmentsRoutes.post(
  "/:id/sections/:sectionId/questions",
  requireAuth,
  requireRole(["ADMIN"]),
  addQuestion
);
assessmentsRoutes.patch(
  "/:id/sections/:sectionId/questions/:pqId",
  requireAuth,
  requireRole(["ADMIN"]),
  patchQuestion
);
assessmentsRoutes.delete(
  "/:id/sections/:sectionId/questions/:pqId",
  requireAuth,
  requireRole(["ADMIN"]),
  removeQuestion
);

assessmentsRoutes.post(
  "/:id/assignments",
  requireAuth,
  requireRole(["ADMIN"]),
  assign
);
assessmentsRoutes.get(
  "/:id/assignments",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  getAssignments
);
assessmentsRoutes.delete(
  "/:id/assignments/:assignmentId",
  requireAuth,
  requireRole(["ADMIN"]),
  deleteAssignment
);
assessmentsRoutes.patch(
  "/:id/assignments/:assignmentId",
  requireAuth,
  requireRole(["ADMIN"]),
  updateAssignmentHandler
);

assessmentsRoutes.get(
  "/:id/submissions",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  getSubmissions
);
assessmentsRoutes.get(
  "/:id/submissions/:attemptId",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  getSubmissionById
);
assessmentsRoutes.patch(
  "/:id/submissions/:attemptId/answers/:answerId",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  markAnswerHandler
);
assessmentsRoutes.post(
  "/:id/submissions/:attemptId/finalize-marking",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  finalizeMarkingHandler
);

assessmentsRoutes.post(
  "/:id/start",
  requireAuth,
  requireRole(["STUDENT", "ADMIN", "TUTOR"]),
  start
);
assessmentsRoutes.get(
  "/:id/result",
  requireAuth,
  requireRole(["STUDENT"]),
  getPaperResultHandler
);
assessmentsRoutes.get(
  "/:id/latest-released-attempt",
  requireAuth,
  getLatestReleasedAttempt
);

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
assessmentsRoutes.patch("/:id", requireAuth, requireRole(["ADMIN"]), updateAssessmentHandler);
assessmentsRoutes.delete("/:id", requireAuth, requireRole(["ADMIN"]), deleteAssessmentHandler);

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
  create
);

export { assessmentsRoutes };
