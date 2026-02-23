import type { NextFunction, Request, Response } from "express";
import type { ZodSchema } from "zod";
import { createLogger } from "../../shared/utils/logger.js";

const logger = createLogger("validate");

export function validateBody(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      logger.debug("Body validation failed", {
        method: req.method,
        path:   req.originalUrl,
        issues: parsed.error.issues,
      });
      res.status(400).json({ message: "Invalid payload", issues: parsed.error.issues });
      return;
    }
    req.body = parsed.data;
    next();
  };
}

export function validateQuery(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const parsed = schema.safeParse(req.query);
    if (!parsed.success) {
      logger.debug("Query validation failed", {
        method: req.method,
        path:   req.originalUrl,
        issues: parsed.error.issues,
      });
      res.status(400).json({ message: "Invalid query", issues: parsed.error.issues });
      return;
    }
    // Express 5 exposes req.query via a getter-only property, so we don't mutate it.
    next();
  };
}
