/**
 * @swagger
 * tags:
 *   name: Quizzes (RBAC)
 *   description: Quiz management with RBAC and answer visibility controls
 */

import { Router } from "express";
import {
  getQuizAttempts,
  getStudentQuizResults,
  updateQuizVisibility,
} from "../controllers/quizzes.controller.js";
import { guard } from "../lib/rbac/guard.js";
import { requireAuth } from "../core/middleware/auth.js";
import { onlyAdminOrTutor, requirePermission } from "../core/guards/rbac.js";

const router = Router();

/**
 * @swagger
 * /api/quizzes/{quizId}/attempts:
 *   get:
 *     summary: Get quiz attempts
 *     tags: [Quizzes (RBAC)]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: quizId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Quiz attempts
 */
router.get(
  "/quizzes/:quizId/attempts",
  requireAuth,
  getQuizAttempts
);

/**
 * @swagger
 * /api/students/{studentId}/quiz-results:
 *   get:
 *     summary: Get quiz results for a specific student
 *     tags: [Quizzes (RBAC)]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: studentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Student quiz results
 */
router.get(
  "/students/:studentId/quiz-results",
  requireAuth,
  guard({
    roles: ["PARENT", "TUTOR", "ADMIN"],
    ownership: {
      type: "student",
      idParam: "studentId",
      allowSelf: false, // Students use the other endpoint
      allowParent: true,
      allowTutor: true,
    },
  }),
  getStudentQuizResults
);

/**
 * @swagger
 * /api/quizzes/{quizId}/visibility:
 *   patch:
 *     summary: Update quiz visibility settings (Tutor/Admin)
 *     tags: [Quizzes (RBAC)]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: quizId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Visibility updated
 */
router.patch(
  "/quizzes/:quizId/visibility",
  requireAuth,
  onlyAdminOrTutor,
  requirePermission("quiz:write"),
  updateQuizVisibility
);

export default router;
