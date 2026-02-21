import type { NextFunction, Request, Response } from "express";
import { logError } from "../../shared/utils/logger.js";
import { isDatabaseAuthError } from "../../shared/utils/db-errors.js";

type HttpError = Error & { status?: number; statusCode?: number };

export function errorHandler(
  err: HttpError,
  _req: Request,
  res: Response,
  _next: NextFunction
) {
  const isDbAuthFailure = isDatabaseAuthError(err);
  const status = isDbAuthFailure ? 503 : (err.statusCode ?? err.status ?? 500);
  const isDev = process.env.NODE_ENV !== "production";
  const message = isDbAuthFailure
    ? "Database authentication is currently unavailable. Please try again later."
    : status >= 500 && !isDev
      ? "Internal server error"
      : err.message;

  logError("Request failed", {
    status,
    message,
    error: err.message,
    stack: err.stack,
  });
  res.status(status).json({ message });
}
