import type { NextFunction, Request, Response } from "express";
import type { ZodSchema } from "zod";

export function validateBody(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ message: "Invalid payload", issues: parsed.error.issues });
      return;
    }
    req.body = parsed.data;
    next();
  };
}

export function validateQuery(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const parsed = schema.safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({ message: "Invalid query", issues: parsed.error.issues });
      return;
    }
    // Express 5 exposes req.query via a getter-only property, so reassigning it throws.
    // We keep validation behavior without mutating the request object.
    next();
  };
}
