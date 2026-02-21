import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber } from "../shared/utils/parse.js";
import { createResource, getResourceById, listResources } from "../services/resources.service.js";
import { resourceQuerySchema } from "../shared/validators/index.js";

export const list = asyncHandler(async (req: Request, res: Response) => {
  const parsed = resourceQuerySchema.safeParse({
    lessonId: req.query.lessonId ? Number(req.query.lessonId) : undefined,
  });
  if (!parsed.success) {
    res.status(400).json({ message: "Invalid query", issues: parsed.error.issues });
    return;
  }
  const data = await listResources(parsed.data.lessonId);
  res.json(data);
});

export const getById = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid resource id" });
    return;
  }
  const resource = await getResourceById(id);
  if (!resource) {
    res.status(404).json({ message: "Resource not found" });
    return;
  }
  res.json(resource);
});

export const create = asyncHandler(async (req: Request, res: Response) => {
  const created = await createResource(req.body);
  res.status(201).json(created);
});
