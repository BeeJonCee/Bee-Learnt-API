import { Router } from "express";
import { requireAuth } from "../../core/middleware/auth.js";
import { onlyAdminOrTutor, onlyParent } from "../../core/guards/rbac.js";
import { getStudentSummary, getParentSummary, createRecord } from "./attendance.controller.js";

const attendanceRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Attendance
 *   description: Student attendance tracking
 */

/**
 * @swagger
 * /api/attendance/me:
 *   get:
 *     summary: Get attendance summary for the current user (student)
 *     tags: [Attendance]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: from
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: to
 *         schema:
 *           type: string
 *           format: date
 *     responses:
 *       200:
 *         description: Attendance summary
 */
attendanceRoutes.get("/me", requireAuth, getStudentSummary);

/**
 * @swagger
 * /api/attendance/students/{studentId}:
 *   get:
 *     summary: Get attendance summary for a specific student (tutor/admin)
 *     tags: [Attendance]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: studentId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: from
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: to
 *         schema:
 *           type: string
 *           format: date
 *     responses:
 *       200:
 *         description: Student attendance summary
 */
attendanceRoutes.get("/students/:studentId", requireAuth, onlyAdminOrTutor, getStudentSummary);

/**
 * @swagger
 * /api/attendance/parent/children:
 *   get:
 *     summary: Get attendance summary for all linked children (parent)
 *     tags: [Attendance]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: from
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: to
 *         schema:
 *           type: string
 *           format: date
 *     responses:
 *       200:
 *         description: Children attendance summaries
 */
attendanceRoutes.get("/parent/children", requireAuth, onlyParent, getParentSummary);

/**
 * @swagger
 * /api/attendance:
 *   post:
 *     summary: Create an attendance record (tutor/admin)
 *     tags: [Attendance]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [studentId, date, status]
 *             properties:
 *               studentId:
 *                 type: string
 *               date:
 *                 type: string
 *                 format: date
 *               status:
 *                 type: string
 *                 enum: [present, absent, late, excused]
 *               notes:
 *                 type: string
 *     responses:
 *       201:
 *         description: Attendance record created
 */
attendanceRoutes.post("/", requireAuth, onlyAdminOrTutor, createRecord);

export { attendanceRoutes };
