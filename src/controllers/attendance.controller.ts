import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseUuid } from "../shared/utils/parse.js";
import {
  createAttendanceRecord,
  getParentAttendanceSummary,
  getStudentAttendanceSummary,
} from "../services/attendance.service.js";

const parseDate = (value?: string | string[]) => {
  if (!value || Array.isArray(value)) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

export const summary = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const from = parseDate(req.query.from as string | undefined) ?? new Date(Date.now() - 6 * 86400000);
  const to = parseDate(req.query.to as string | undefined) ?? new Date();

  if ((req.query.from && !from) || (req.query.to && !to)) {
    res.status(400).json({ message: "Invalid date range" });
    return;
  }

  if (user.role === "PARENT") {
    const data = await getParentAttendanceSummary(user.id, from, to);
    res.json(data);
    return;
  }

  if (user.role === "ADMIN") {
    const studentId = parseUuid(req.query.studentId as string | undefined);
    if (!studentId) {
      res.status(400).json({ message: "studentId is required for admin" });
      return;
    }
    const data = await getStudentAttendanceSummary(studentId, from, to);
    res.json(data);
    return;
  }

  const data = await getStudentAttendanceSummary(user.id, from, to);
  res.json(data);
});

export const create = asyncHandler(async (req: Request, res: Response) => {
  const created = await createAttendanceRecord({
    studentId: req.body.studentId,
    date: new Date(req.body.date),
    status: req.body.status,
    notes: req.body.notes ?? null,
  });
  res.status(201).json(created);
});
