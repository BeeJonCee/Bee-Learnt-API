/**
 * Progress Routes
 *
 * RBAC Rules:
 * - STUDENT: Can view/update their own progress
 * - PARENT: Can view linked children's progress (read-only)
 * - TUTOR: Can view all students' progress
 * - ADMIN: Full access to all progress data
 */

import { Router } from "express";
import {
  list,
  summary,
  update,
  getStudentProgress,
  getParentDashboard,
  getModuleProgress,
  getUserMastery,
  getWeakTopics,
  getStrongTopics,
  getOverallMastery,
} from "../controllers/progress.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import {
  requirePermission,
  onlyParent,
  onlyRoles,
} from "../core/guards/rbac.js";
import {
  guard,
  requireOwnership,
} from "../lib/rbac/guard.js";

const progressRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Progress
 *   description: Progress tracking, summaries, and dashboards
 */

// ============ BASIC PROGRESS ENDPOINTS (User's Own Progress) ============

// Get user's own progress summary
/**
 * @swagger
 * /api/progress/summary:
 *   get:
 *     summary: Retrieve the authenticated user's progress summary
 *     tags: [Progress]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Progress summary metrics
 */
progressRoutes.get(
  "/summary",
  requireAuth,
  requirePermission("progress:read:own"),
  summary
);

// List user's own progress entries
/**
 * @swagger
 * /api/progress:
 *   get:
 *     summary: List detailed progress entries for the user
 *     tags: [Progress]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Progress entries
 */
progressRoutes.get(
  "/",
  requireAuth,
  requirePermission("progress:read:own"),
  list
);

// Update user's own progress (students updating their progress)
/**
 * @swagger
 * /api/progress:
 *   post:
 *     summary: Update learning progress for the current user
 *     tags: [Progress]
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
 *         description: Progress updated
 */
progressRoutes.post(
  "/",
  requireAuth,
  requirePermission("progress:read:own", "progress:write"),
  update
);

// ============ PARENT DASHBOARD ============

// Parent dashboard - view all linked children's progress
/**
 * @swagger
 * /api/progress/parent/dashboard:
 *   get:
 *     summary: Parent dashboard view of linked student progress
 *     tags: [Progress]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Parent dashboard data
 */
progressRoutes.get(
  "/parent/dashboard",
  requireAuth,
  onlyParent,
  getParentDashboard
);

// ============ STUDENT-SPECIFIC PROGRESS (RBAC Protected) ============

// Get comprehensive progress for a specific student
// Accessible by: Student (self), Parent (linked), Tutor, Admin
/**
 * @swagger
 * /api/progress/students/{studentId}:
 *   get:
 *     summary: Retrieve comprehensive progress for a student
 *     tags: [Progress]
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
progressRoutes.get(
  "/students/:studentId",
  requireAuth,
  guard({
    permissions: ["progress:read:own", "progress:read:linked", "progress:read:all"],
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

// Get detailed progress for a specific module for a student
// Accessible by: Student (self), Parent (linked), Tutor, Admin
/**
 * @swagger
 * /api/progress/students/{studentId}/modules/{moduleId}:
 *   get:
 *     summary: Module-level progress insights for a student
 *     tags: [Progress]
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
progressRoutes.get(
  "/students/:studentId/modules/:moduleId",
  requireAuth,
  guard({
    permissions: ["progress:read:own", "progress:read:linked", "progress:read:all"],
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

// ============ TOPIC MASTERY ANALYTICS ============

/**
 * @swagger
 * /api/progress/mastery:
 *   get:
 *     summary: Get topic mastery breakdown for a user
 *     tags: [Progress]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: userId
 *         schema:
 *           type: string
 *         description: User ID (defaults to authenticated user)
 *       - in: query
 *         name: subjectId
 *         schema:
 *           type: integer
 *         description: Filter by subject ID
 *     responses:
 *       200:
 *         description: Topic mastery data
 */
progressRoutes.get(
  "/mastery",
  requireAuth,
  getUserMastery
);

/**
 * @swagger
 * /api/progress/mastery/weak:
 *   get:
 *     summary: Get user's weakest topics
 *     tags: [Progress]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: userId
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 5
 *       - in: query
 *         name: minQuestions
 *         schema:
 *           type: integer
 *           default: 3
 *     responses:
 *       200:
 *         description: Weakest topics list
 */
progressRoutes.get(
  "/mastery/weak",
  requireAuth,
  getWeakTopics
);

/**
 * @swagger
 * /api/progress/mastery/strong:
 *   get:
 *     summary: Get user's strongest topics
 *     tags: [Progress]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: userId
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 5
 *       - in: query
 *         name: minQuestions
 *         schema:
 *           type: integer
 *           default: 3
 *     responses:
 *       200:
 *         description: Strongest topics list
 */
progressRoutes.get(
  "/mastery/strong",
  requireAuth,
  getStrongTopics
);

/**
 * @swagger
 * /api/progress/mastery/overall:
 *   get:
 *     summary: Get overall mastery percentage across all subjects
 *     tags: [Progress]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: userId
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Overall mastery percentage
 */
progressRoutes.get(
  "/mastery/overall",
  requireAuth,
  getOverallMastery
);

export { progressRoutes };
