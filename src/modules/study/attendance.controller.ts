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
