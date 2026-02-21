import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber } from "../shared/utils/parse.js";
import { createLesson, getLessonById, listLessons, updateLesson } from "../services/lessons.service.js";
import { lessonQuerySchema } from "../shared/validators/index.js";

export const list = asyncHandler(async (req: Request, res: Response) => {
  const parsed = lessonQuerySchema.safeParse({
    moduleId: req.query.moduleId ? Number(req.query.moduleId) : undefined,
  });
  if (!parsed.success) {
    res.status(400).json({ message: "Invalid query", issues: parsed.error.issues });
    return;
  }
  const data = await listLessons(parsed.data.moduleId);
  res.json(data);
});

export const getById = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid lesson id" });
    return;
  }
  const lesson = await getLessonById(id);
  if (!lesson) {
    res.status(404).json({ message: "Lesson not found" });
    return;
  }
  res.json(lesson);
});

export const create = asyncHandler(async (req: Request, res: Response) => {
  const created = await createLesson(req.body);
  res.status(201).json(created);
});

export const update = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid lesson id" });
    return;
  }
  const updated = await updateLesson(id, req.body);
  if (!updated) {
    res.status(404).json({ message: "Lesson not found" });
    return;
  }
  res.json(updated);
});
