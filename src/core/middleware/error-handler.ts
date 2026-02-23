import type { NextFunction, Request, Response } from "express";
import { createLogger } from "../../shared/utils/logger.js";
import { isDatabaseAuthError } from "../../shared/utils/db-errors.js";

type HttpError = Error & { status?: number; statusCode?: number };

const logger = createLogger("error-handler");

export function errorHandler(
  err: HttpError,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  const isDbAuthFailure = isDatabaseAuthError(err);
  const status = isDbAuthFailure
    ? 503
    : (err.statusCode ?? err.status ?? 500);

  const isDev  = process.env.NODE_ENV !== "production";

  const message = isDbAuthFailure
    ? "Database authentication is currently unavailable. Please try again later."
    : status >= 500 && !isDev
    ? "Internal server error"
    : err.message;

  const meta = {
    method: req.method,
    path:   req.originalUrl,
    status,
    error:  err.message,
    ...(isDev && err.stack ? { stack: err.stack } : {}),
  };

  if (status >= 500) {
    logger.error("Unhandled request error", meta);
  } else {
    // 4xx errors are expected (validation, auth) — warn is enough
    logger.warn("Request rejected", meta);
  }

  res.status(status).json({ message });
}
