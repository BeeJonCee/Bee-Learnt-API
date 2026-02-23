import type { Request, Response } from "express";
import { createLogger } from "../../shared/utils/logger.js";

const logger = createLogger("router");

export function notFound(req: Request, res: Response): void {
  logger.warn("Route not found", { method: req.method, path: req.originalUrl });
  res.status(404).json({ message: "Not found" });
}
