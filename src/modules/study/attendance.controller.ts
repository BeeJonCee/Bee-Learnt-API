import type { Request, Response } from "express";
import { asyncHandler } from "../../core/middleware/async-handler.js";
import {
  getStudentAttendanceSummary,
  getParentAttendanceSummary,
  createAttendanceRecord,
  type AttendanceStatus,
} from "./attendance.service.js";

function parseDateParam(value: string | undefined, fallback: Date): Date {
  if (!value) return fallback;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? fallback : d;
}

export const getStudentSummary = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const studentId = (req.params.studentId as string) || userId;

  const now = new Date();
  const defaultFrom = new Date(now.getFullYear(), now.getMonth(), 1);
  const from = parseDateParam(req.query.from as string | undefined, defaultFrom);
  const to = parseDateParam(req.query.to as string | undefined, now);

  const summary = await getStudentAttendanceSummary(studentId, from, to);
  res.json({ studentId, from: from.toISOString(), to: to.toISOString(), summary });
});

export const getParentSummary = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const now = new Date();
  const defaultFrom = new Date(now.getFullYear(), now.getMonth(), 1);
  const from = parseDateParam(req.query.from as string | undefined, defaultFrom);
  const to = parseDateParam(req.query.to as string | undefined, now);

  const data = await getParentAttendanceSummary(userId, from, to);
  res.json({ from: from.toISOString(), to: to.toISOString(), children: data });
});

// Legacy compatibility endpoint for frontend widgets that expect
// /api/attendance/summary with direct summary payload shapes.
export const getSummary = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  const role = req.user?.role ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const now = new Date();
  const defaultFrom = new Date(now.getFullYear(), now.getMonth(), 1);
  const from = parseDateParam(req.query.from as string | undefined, defaultFrom);
  const to = parseDateParam(req.query.to as string | undefined, now);

  const requestedStudentIdRaw = req.query.studentId;
  const requestedStudentId =
    typeof requestedStudentIdRaw === "string" && requestedStudentIdRaw.trim().length > 0
      ? requestedStudentIdRaw.trim()
      : null;

  if (requestedStudentId) {
    if (role === "STUDENT" && requestedStudentId !== userId) {
      res.status(403).json({ message: "Forbidden" });
      return;
    }
    const summary = await getStudentAttendanceSummary(requestedStudentId, from, to);
    res.json(summary);
    return;
  }

  if (role === "PARENT") {
    const children = await getParentAttendanceSummary(userId, from, to);
    res.json(children);
    return;
  }

  const summary = await getStudentAttendanceSummary(userId, from, to);
  res.json(summary);
});

export const createRecord = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const { studentId, date, status, notes } = req.body as {
    studentId: string;
    date: string;
    status: AttendanceStatus;
    notes?: string;
  };

  if (!studentId || !date || !status) {
    res.status(400).json({ message: "studentId, date, and status are required" });
    return;
  }

  const parsedDate = new Date(date);
  if (Number.isNaN(parsedDate.getTime())) {
    res.status(400).json({ message: "Invalid date format" });
    return;
  }

  const record = await createAttendanceRecord({ studentId, date: parsedDate, status, notes });
  res.status(201).json(record);
});
