import { Router } from "express";
import {
  analytics,
  assignUserModules,
  generateReport,
  getUserDetails,
  insights,
  listModules,
  listUserModules,
  listUsers,
  reportStats,
  systemHealth,
  updateUserRole,
  syncSchemaToNeonAuth,
  verifySchemaConsistency,
} from "../controllers/admin.controller.js";
import { requireRole } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { adminAssignModulesSchema, adminUpdateUserRoleSchema } from "../shared/validators/index.js";
import { onlyAdmin, onlyAdminOrTutor, requirePermission } from "../core/guards/rbac.js";

const adminRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Admin
 *   description: High-level analytics, user management, and system operations
 */

// ========== ADMIN ONLY - Analytics & System ==========

/**
 * @swagger
 * /api/admin/analytics:
 *   get:
 *     summary: Platform-wide analytics snapshot
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Aggregated analytics for administrators
 */
adminRoutes.get("/analytics", onlyAdmin, analytics);

/**
 * @swagger
 * /api/admin/insights:
 *   get:
 *     summary: Generate actionable learning insights
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Trend and engagement insights
 */
adminRoutes.get("/insights", onlyAdmin, insights);

/**
 * @swagger
 * /api/admin/system-health:
 *   get:
 *     summary: Report on system health and integrations
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Operational health metrics
 */
adminRoutes.get("/system-health", onlyAdmin, systemHealth);

/**
 * @swagger
 * /api/admin/reports/stats:
 *   get:
 *     summary: Fetch report statistics
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Report statistics payload
 */
adminRoutes.get("/reports/stats", onlyAdmin, reportStats);

/**
 * @swagger
 * /api/admin/reports/generate:
 *   post:
 *     summary: Trigger generation of a custom report
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       202:
 *         description: Report generation started
 */
adminRoutes.post("/reports/generate", onlyAdmin, generateReport);

// ========== ADMIN ONLY - User Management ==========

/**
 * @swagger
 * /api/admin/users:
 *   get:
 *     summary: List users with administrative filters
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Array of users
 */
adminRoutes.get("/users", onlyAdmin, listUsers);

/**
 * @swagger
 * /api/admin/users/{userId}:
 *   get:
 *     summary: View details for a specific user
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User profile details
 *       404:
 *         description: User not found
 */
adminRoutes.get("/users/:userId", onlyAdminOrTutor, getUserDetails);

/**
 * @swagger
 * /api/admin/users/{userId}/role:
 *   put:
 *     summary: Update a user's role
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
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
 *         description: Updated user role
 */
adminRoutes.put(
  "/users/:userId/role",
  onlyAdmin,
  validateBody(adminUpdateUserRoleSchema),
  updateUserRole
);

// ========== ADMIN & TUTOR - Module Management ==========
// Tutors can view modules and assign them to students

/**
 * @swagger
 * /api/admin/modules:
 *   get:
 *     summary: Browse modules from an admin or tutor perspective
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Module list scoped for administrators/tutors
 */
adminRoutes.get("/modules", onlyAdminOrTutor, listModules);

/**
 * @swagger
 * /api/admin/users/{userId}/modules:
 *   get:
 *     summary: View modules assigned to a user
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Modules linked to the user
 */
adminRoutes.get("/users/:userId/modules", onlyAdminOrTutor, listUserModules);

/**
 * @swagger
 * /api/admin/users/{userId}/modules:
 *   post:
 *     summary: Assign modules to a learner
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: userId
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
 *         description: Modules assigned successfully
 */
adminRoutes.post(
  "/users/:userId/modules",
  onlyAdminOrTutor,
  requirePermission("module:assign"),
  validateBody(adminAssignModulesSchema),
  assignUserModules
);

// ========== ADMIN ONLY - Schema Sync ==========

/**
 * @swagger
 * /api/admin/sync/neon-auth:
 *   post:
 *     summary: Synchronise RBAC schema with Neon Auth
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       202:
 *         description: Sync initiated
 */
adminRoutes.post("/sync/neon-auth", onlyAdmin, syncSchemaToNeonAuth);

/**
 * @swagger
 * /api/admin/schema/verify:
 *   get:
 *     summary: Verify schema alignment between BeeLearnt and Neon Auth
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Schema verification results
 */
adminRoutes.get("/schema/verify", onlyAdmin, verifySchemaConsistency);

export { adminRoutes };
