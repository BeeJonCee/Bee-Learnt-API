/**
 * HTTP Request Logger Middleware
 *
 * Per request:
 *  1. Generates a unique `requestId` (UUID v4).
 *  2. Wraps the entire async pipeline in an AsyncLocalStorage context so that
 *     every logger call downstream automatically includes { requestId, userId }.
 *  3. Sets the `X-Request-Id` response header for client-side tracing.
 *  4. Logs the incoming request at DEBUG level.
 *  5. Logs the outgoing response at INFO / WARN / ERROR based on status code,
 *     including duration in milliseconds and the authenticated userId (if any).
 */

import type { Request, Response, NextFunction } from "express";
import {
  createLogger,
  createRequestContext,
  requestContextStore,
} from "../../shared/utils/logger.js";

const logger = createLogger("http");

// Health-check path — skip verbose logging to reduce noise
const SILENT_PATHS = new Set(["/health", "/", "/favicon.ico"]);

export function requestLogger(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const silent = SILENT_PATHS.has(req.path);
  const context = createRequestContext(req.method, req.path);

  // Expose the request ID on the response header immediately
  res.setHeader("X-Request-Id", context.requestId);
  // Also expose on res.locals so downstream handlers can read it
  res.locals["requestId"] = context.requestId;

  requestContextStore.run(context, () => {
    const startedAt = Date.now();

    if (!silent) {
      const ip = (req.ip ?? req.socket?.remoteAddress ?? "unknown").replace(
        "::ffff:",
        "",
      );
      const ua = req.header("user-agent") ?? "-";

      logger.debug(`→ ${req.method} ${req.originalUrl}`, {
        ip,
        userAgent: ua,
      });
    }

    res.on("finish", () => {
      const duration = Date.now() - startedAt;
      const status   = res.statusCode;

      // Attach the userId now that the auth middleware has run (it sets req.user)
      if (req.user?.id) {
        context.userId = req.user.id;
      }

      if (silent && status < 400) {
        // Suppress health-check noise in the happy path
        return;
      }

      const level =
        status >= 500 ? "error"
        : status >= 400 ? "warn"
        : "info";

      logger[level](`← ${req.method} ${req.originalUrl} ${status} (${duration}ms)`, {
        status,
        duration,
        ...(req.user?.id ? { userId: req.user.id } : {}),
      });
    });

    next();
  });
}
