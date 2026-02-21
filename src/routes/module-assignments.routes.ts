/**
 * @swagger
 * tags:
 *   name: Module Assignments
 *   description: Assign and manage module assignments with RBAC
 */

import { Router } from "express";
import {
  assignModuleToStudent,
  getStudentModules,
  getAllModuleAssignments,
  getAssignmentDetails,
  updateAssignment,
  deleteAssignment,
  bulkAssignModules,
} from "../controllers/module-assignments.controller.js";
import { guard } from "../lib/rbac/guard.js";
import { requireAuth } from "../core/middleware/auth.js";
import { onlyAdminOrTutor, requirePermission } from "../core/guards/rbac.js";

const router = Router();

/**
 * @swagger
 * /api/module-assignments:
 *   post:
 *     summary: Assign module to a student (Tutor/Admin)
 *     tags: [Module Assignments]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Assignment created
 */
router.post(
  "/module-assignments",
  requireAuth,
  onlyAdminOrTutor,
  requirePermission("module:assign"),
  assignModuleToStudent
);

/**
 * @swagger
 * /api/module-assignments/bulk:
 *   post:
 *     summary: Bulk assign modules (Tutor/Admin)
 *     tags: [Module Assignments]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Bulk assignments created
 */
router.post(
  "/module-assignments/bulk",
  requireAuth,
  onlyAdminOrTutor,
  requirePermission("module:assign"),
  bulkAssignModules
);

/**
 * @swagger
 * /api/module-assignments:
 *   get:
 *     summary: Get all module assignments (Tutor/Admin)
 *     tags: [Module Assignments]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of assignments
 */
router.get(
  "/module-assignments",
  requireAuth,
  onlyAdminOrTutor,
  getAllModuleAssignments
);

/**
 * @swagger
 * /api/students/{studentId}/modules:
 *   get:
 *     summary: Get student's assigned modules
 *     tags: [Module Assignments]
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
 *         description: Student's modules
 */
router.get(
  "/students/:studentId/modules",
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
  getStudentModules
);

/**
 * @swagger
 * /api/module-assignments/{assignmentId}:
 *   get:
 *     summary: Get assignment details
 *     tags: [Module Assignments]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: assignmentId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Assignment details
 */
router.get(
  "/module-assignments/:assignmentId",
  requireAuth,
  guard({
    roles: ["STUDENT", "PARENT", "TUTOR", "ADMIN"],
    ownership: {
      type: "module_assignment",
      idParam: "assignmentId",
      allowSelf: true,
      allowParent: true,
      allowTutor: true,
    },
  }),
  getAssignmentDetails
);

/**
 * @swagger
 * /api/module-assignments/{assignmentId}:
 *   patch:
 *     summary: Update an assignment (Tutor/Admin)
 *     tags: [Module Assignments]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: assignmentId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Updated
 */
router.patch(
  "/module-assignments/:assignmentId",
  requireAuth,
  onlyAdminOrTutor,
  updateAssignment
);

/**
 * @swagger
 * /api/module-assignments/{assignmentId}:
 *   delete:
 *     summary: Delete an assignment (Tutor/Admin)
 *     tags: [Module Assignments]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: assignmentId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Deleted
 */
router.delete(
  "/module-assignments/:assignmentId",
  requireAuth,
  onlyAdminOrTutor,
  deleteAssignment
);

export default router;
