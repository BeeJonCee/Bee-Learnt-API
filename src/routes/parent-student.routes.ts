/**
 * Parent-Student Management Routes
 *
 * Routes for parent-student relationships with RBAC guards.
 *
 * RBAC Rules:
 * - PARENT: Can create student profiles, link/unlink students, view linked students
 * - STUDENT: Can view/update their own profile
 * - TUTOR: Can view assigned students
 * - ADMIN: Full access to all parent-student operations
 */

import { Router } from "express";
import {
  createStudentProfile,
  bulkLinkParentToStudents,
  bulkUnlinkParentFromStudents,
  linkParentToStudent,
  unlinkParentFromStudent,
  getLinkedStudents,
  getStudentDetails,
  updateStudentProfile,
  createParentProfile,
  getParentProfile,
} from "../controllers/parent-student.controller.js";
import { guard } from "../lib/rbac/guard.js";
import { requireAuth } from "../core/middleware/auth.js";
import { onlyRoles } from "../core/guards/rbac.js";

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Parent Student
 *   description: Manage parent, student, and linking flows
 */

// ============ PARENT PROFILE ============

/**
 * @swagger
 * /api/parents/profile:
 *   get:
 *     summary: Retrieve the authenticated parent's profile
 *     tags: [Parent Student]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Parent profile information
 */
router.get(
  "/parents/profile",
  requireAuth,
  onlyRoles("PARENT", "ADMIN"),
  getParentProfile
);

/**
 * @swagger
 * /api/parents/profile:
 *   post:
 *     summary: Create or update the parent profile
 *     tags: [Parent Student]
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
 *         description: Parent profile saved
 */
router.post(
  "/parents/profile",
  requireAuth,
  onlyRoles("PARENT", "ADMIN"),
  createParentProfile
);

// ============ STUDENT MANAGEMENT ============

// Create student profile (parent creates for child)
/**
 * @swagger
 * /api/parents/students:
 *   post:
 *     summary: Create a student profile linked to the parent
 *     tags: [Parent Student]
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
 *         description: Student profile created
 */
router.post(
  "/parents/students",
  requireAuth,
  onlyRoles("PARENT", "ADMIN"),
  createStudentProfile
);

// Get all linked students for a parent
/**
 * @swagger
 * /api/parents/students:
 *   get:
 *     summary: List students linked to the parent account
 *     tags: [Parent Student]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Linked student profiles
 */
router.get(
  "/parents/students",
  requireAuth,
  onlyRoles("PARENT", "ADMIN"),
  getLinkedStudents
);

// Get details of a specific student (requires ownership check)
/**
 * @swagger
 * /api/parents/students/{studentId}:
 *   get:
 *     summary: View details for a linked student
 *     tags: [Parent Student]
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
 *         description: Student profile details
 *       404:
 *         description: Student not found or not linked
 */
router.get(
  "/parents/students/:studentId",
  requireAuth,
  guard({
    roles: ["PARENT", "STUDENT", "TUTOR", "ADMIN"],
    ownership: {
      type: "student",
      idParam: "studentId",
      allowSelf: true,
      allowParent: true,
      allowTutor: true,
    },
  }),
  getStudentDetails
);

// Update student profile (requires ownership check)
/**
 * @swagger
 * /api/parents/students/{studentId}:
 *   patch:
 *     summary: Update a linked student's profile
 *     tags: [Parent Student]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: studentId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Student profile updated
 */
router.patch(
  "/parents/students/:studentId",
  requireAuth,
  guard({
    roles: ["PARENT", "STUDENT", "ADMIN"],
    ownership: {
      type: "student",
      idParam: "studentId",
      allowSelf: true,
      allowParent: true,
    },
  }),
  updateStudentProfile
);

// ============ PARENT-STUDENT LINKING ============

// Bulk link parent to students
router.post(
  "/parents/students/link/bulk",
  requireAuth,
  onlyRoles("PARENT", "ADMIN"),
  bulkLinkParentToStudents
);

// Bulk unlink parent from students
router.delete(
  "/parents/students/link/bulk",
  requireAuth,
  onlyRoles("PARENT", "ADMIN"),
  bulkUnlinkParentFromStudents
);

// Link parent to student
/**
 * @swagger
 * /api/parents/students/{studentId}/link:
 *   post:
 *     summary: Link a parent account to an existing student
 *     tags: [Parent Student]
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
 *         description: Parent linked to student
 */
router.post(
  "/parents/students/:studentId/link",
  requireAuth,
  onlyRoles("PARENT", "ADMIN"),
  linkParentToStudent
);

// Unlink parent from student
/**
 * @swagger
 * /api/parents/students/{studentId}/link:
 *   delete:
 *     summary: Unlink a parent account from a student
 *     tags: [Parent Student]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: studentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       204:
 *         description: Parent unlinked from student
 */
router.delete(
  "/parents/students/:studentId/link",
  requireAuth,
  onlyRoles("PARENT", "ADMIN"),
  unlinkParentFromStudent
);

export default router;
