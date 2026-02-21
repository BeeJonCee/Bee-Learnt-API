import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { searchAll } from "../services/search.service.js";
import { searchQuerySchema } from "../shared/validators/index.js";

export const search = asyncHandler(async (req: Request, res: Response) => {
  const parsed = searchQuerySchema.safeParse({ query: req.query.query });
  if (!parsed.success) {
    res.status(400).json({ message: "Query too short" });
    return;
  }

  const results = await searchAll(parsed.data.query);
  res.json(results);
});
