import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber } from "../shared/utils/parse.js";
import {
  listSubjectResources,
  getSubjectResourceById,
  createSubjectResource,
  deleteSubjectResource,
} from "../services/subject-resources.service.js";
import { subjectResourceQuerySchema } from "../shared/validators/subject-resources.validators.js";

export const list = asyncHandler(async (req: Request, res: Response) => {
  const parsed = subjectResourceQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ message: "Invalid query", issues: parsed.error.issues });
    return;
  }
  const data = await listSubjectResources(parsed.data);
  res.json(data);
});

export const getById = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid resource id" });
    return;
  }
  const resource = await getSubjectResourceById(id);
  if (!resource) {
    res.status(404).json({ message: "Subject resource not found" });
    return;
  }
  res.json(resource);
});

export const create = asyncHandler(async (req: Request, res: Response) => {
  const created = await createSubjectResource(req.body);
  res.status(201).json(created);
});

export const remove = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid resource id" });
    return;
  }
  const deleted = await deleteSubjectResource(id);
  if (!deleted) {
    res.status(404).json({ message: "Subject resource not found" });
    return;
  }
  res.json({ message: "Deleted", id: deleted.id });
});
