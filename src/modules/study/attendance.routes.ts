import { Router } from "express";
import { requireAuth } from "../../core/middleware/auth.js";
import { getStudentSummary, getParentSummary, createRecord } from "./attendance.controller.js";

export const attendanceRoutes = Router();

attendanceRoutes.use(requireAuth);

// GET /attendance/student            → own attendance summary
// GET /attendance/student/:studentId → specific student's summary (parent/admin)
attendanceRoutes.get("/student", getStudentSummary);
attendanceRoutes.get("/student/:studentId", getStudentSummary);

// GET /attendance/parent → parent's children attendance summary
attendanceRoutes.get("/parent", getParentSummary);

// POST /attendance → create an attendance record (admin/tutor)
attendanceRoutes.post("/", createRecord);
