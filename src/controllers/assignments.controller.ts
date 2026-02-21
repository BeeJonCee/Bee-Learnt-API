import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber } from "../shared/utils/parse.js";
import {
  createAssignment,
  getAssignmentById,
  listAssignments,
  updateAssignment,
} from "../services/assignments.service.js";
import { assignmentQuerySchema } from "../shared/validators/index.js";

export const list = asyncHandler(async (req: Request, res: Response) => {
  const parsed = assignmentQuerySchema.safeParse({
    moduleId: req.query.moduleId ? Number(req.query.moduleId) : undefined,
    grade: req.query.grade ? Number(req.query.grade) : undefined,
  });
  if (!parsed.success) {
    res.status(400).json({ message: "Invalid query", issues: parsed.error.issues });
    return;
  }
  const data = await listAssignments(parsed.data.moduleId, parsed.data.grade);
  res.json(data);
});

export const getById = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assignment id" });
    return;
  }
  const assignment = await getAssignmentById(id);
  if (!assignment) {
    res.status(404).json({ message: "Assignment not found" });
    return;
  }
  res.json(assignment);
});

export const create = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  const createdBy = userId ?? undefined;
  const created = await createAssignment(req.body, createdBy);
  res.status(201).json(created);
});

export const update = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assignment id" });
    return;
  }

  const updated = await updateAssignment(id, req.body);
  if (!updated) {
    res.status(404).json({ message: "Assignment not found" });
    return;
  }

  res.json(updated);
});
