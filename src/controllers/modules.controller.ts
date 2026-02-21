import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber } from "../shared/utils/parse.js";
import {
  createModule,
  deleteModule,
  getModuleById,
  listModules,
  updateModule,
} from "../services/modules.service.js";
import { moduleQuerySchema } from "../shared/validators/index.js";

export const list = asyncHandler(async (req: Request, res: Response) => {
  const parsed = moduleQuerySchema.safeParse({
    subjectId: req.query.subjectId ? Number(req.query.subjectId) : undefined,
    grade: req.query.grade ? Number(req.query.grade) : undefined,
  });
  if (!parsed.success) {
    res.status(400).json({ message: "Invalid query", issues: parsed.error.issues });
    return;
  }
  const data = await listModules(parsed.data.subjectId, parsed.data.grade);
  res.json(data);
});

export const getById = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid module id" });
    return;
  }
  const moduleRow = await getModuleById(id);
  if (!moduleRow) {
    res.status(404).json({ message: "Module not found" });
    return;
  }
  res.json(moduleRow);
});

export const create = asyncHandler(async (req: Request, res: Response) => {
  const created = await createModule(req.body);
  res.status(201).json(created);
});

export const update = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid module id" });
    return;
  }
  const updated = await updateModule(id, req.body);
  if (!updated) {
    res.status(404).json({ message: "Module not found" });
    return;
  }
  res.json(updated);
});

export const remove = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid module id" });
    return;
  }
  const deleted = await deleteModule(id);
  if (!deleted) {
    res.status(404).json({ message: "Module not found" });
    return;
  }
  res.json({ success: true });
});
