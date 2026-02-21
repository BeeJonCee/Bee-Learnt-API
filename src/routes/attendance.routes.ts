import { Router } from "express";
import { create, summary } from "../controllers/attendance.controller.js";
import { requireAuth, requireRole } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { attendanceCreateSchema } from "../shared/validators/index.js";

const attendanceRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Attendance
 *   description: Track learner attendance records
 */

/**
 * @swagger
 * /api/attendance/summary:
 *   get:
 *     summary: Attendance summary for current context
 *     tags: [Attendance]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Attendance summary data
 */
attendanceRoutes.get("/summary", requireAuth, summary);

/**
 * @swagger
 * /api/attendance/records:
 *   post:
 *     summary: Record attendance for learners
 *     tags: [Attendance]
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
 *         description: Attendance recorded
 */
attendanceRoutes.post(
  "/records",
  requireRole(["ADMIN"]),
  validateBody(attendanceCreateSchema),
  create
);

export { attendanceRoutes };
