import type { Request, Response, NextFunction } from "express";

/**
 * Logs every incoming HTTP request and its response status + timing.
 */
export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const start = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - start;
    const status = res.statusCode;
    const level = status >= 500 ? "ERROR" : status >= 400 ? "WARN" : "INFO";
    console.log(
      `[${level}] ${req.method} ${req.originalUrl} → ${status} (${duration}ms)`,
    );
  });

  next();
}
