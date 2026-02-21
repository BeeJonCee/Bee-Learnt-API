import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber } from "../shared/utils/parse.js";
import {
  createSubject,
  getSubjectById,
  listModulesForSubject,
  listSubjects,
  updateSubject,
} from "../services/subjects.service.js";

export const list = asyncHandler(async (_req: Request, res: Response) => {
  const data = await listSubjects();
  res.json(data);
});

export const getById = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid subject id" });
    return;
  }
  const subject = await getSubjectById(id);
  if (!subject) {
    res.status(404).json({ message: "Subject not found" });
    return;
  }
  res.json(subject);
});

export const listModules = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid subject id" });
    return;
  }
  const modules = await listModulesForSubject(id);
  res.json(modules);
});

export const create = asyncHandler(async (req: Request, res: Response) => {
  const created = await createSubject(req.body);
  res.status(201).json(created);
});

export const update = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid subject id" });
    return;
  }
  const updated = await updateSubject(id, req.body);
  if (!updated) {
    res.status(404).json({ message: "Subject not found" });
    return;
  }
  res.json(updated);
});
