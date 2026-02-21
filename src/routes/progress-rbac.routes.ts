/**
 * @swagger
 * tags:
 *   name: Progress (RBAC)
 *   description: Student progress tracking with RBAC guards
 */

import { Router } from "express";
import {
  getStudentProgress,
  getParentDashboard,
  getModuleProgress,
} from "../controllers/progress.controller.js";
import { guard } from "../lib/rbac/guard.js";
import { requireAuth } from "../core/middleware/auth.js";
import { onlyParent } from "../core/guards/rbac.js";

const router = Router();

/**
 * @swagger
 * /api/students/{studentId}/progress:
 *   get:
 *     summary: Get comprehensive progress for a student
 *     tags: [Progress (RBAC)]
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
 *         description: Student progress data
 */
router.get(
  "/students/:studentId/progress",
  requireAuth,
  guard({
    roles: ["STUDENT", "PARENT", "TUTOR", "ADMIN"],
    ownership: {
      type: "student",
      idParam: "studentId",
      allowSelf: true,
      allowParent: true,
      allowTutor: true,
    },
  }),
  getStudentProgress
);

/**
 * @swagger
 * /api/students/{studentId}/modules/{moduleId}/progress:
 *   get:
 *     summary: Get detailed progress for a specific module
 *     tags: [Progress (RBAC)]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: studentId
 *         required: true
 *         schema:
 *           type: string
 *       - in: path
 *         name: moduleId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Module progress data
 */
router.get(
  "/students/:studentId/modules/:moduleId/progress",
  requireAuth,
  guard({
    roles: ["STUDENT", "PARENT", "TUTOR", "ADMIN"],
    ownership: {
      type: "student",
      idParam: "studentId",
      allowSelf: true,
      allowParent: true,
      allowTutor: true,
    },
  }),
  getModuleProgress
);

/**
 * @swagger
 * /api/parents/dashboard:
 *   get:
 *     summary: Parent dashboard - view all linked children's progress
 *     tags: [Progress (RBAC)]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Parent dashboard data
 *       403:
 *         description: Parent role required
 */
router.get(
  "/parents/dashboard",
  requireAuth,
  onlyParent,
  getParentDashboard
);

export default router;
