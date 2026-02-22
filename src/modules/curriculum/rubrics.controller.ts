import type { Request, Response } from "express";
import { asyncHandler } from "../../core/middleware/async-handler.js";
import { parseNumber } from "../../shared/utils/parse.js";
import {
  listRubrics,
  getRubricById,
  createRubric,
  updateRubric,
} from "./rubrics.service.js";

export const list = asyncHandler(async (req: Request, res: Response) => {
  const subjectId = req.query.subjectId
    ? parseNumber(req.query.subjectId as string)
    : undefined;
  const data = await listRubrics(subjectId ?? undefined);
  res.json(data);
});

export const getById = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid rubric id" });
    return;
  }
  const rubric = await getRubricById(id);
  if (!rubric) {
    res.status(404).json({ message: "Rubric not found" });
    return;
  }
  res.json(rubric);
});

export const create = asyncHandler(async (req: Request, res: Response) => {
  const { title, subjectId, criteria } = req.body as {
    title?: unknown;
    subjectId?: unknown;
    criteria?: unknown;
  };

  if (typeof title !== "string" || !title.trim()) {
    res.status(400).json({ message: "title is required" });
    return;
  }
  if (!Array.isArray(criteria) || criteria.length === 0) {
    res.status(400).json({ message: "criteria must be a non-empty array" });
    return;
  }

  const created = await createRubric(
    {
      title: title.trim(),
      subjectId: typeof subjectId === "number" ? subjectId : undefined,
      criteria,
    },
    req.user?.id,
  );
  res.status(201).json(created);
});

export const update = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid rubric id" });
    return;
  }
  const updated = await updateRubric(id, req.body);
  if (!updated) {
    res.status(404).json({ message: "Rubric not found" });
    return;
  }
  res.json(updated);
});
