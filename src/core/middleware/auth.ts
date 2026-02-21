import type { NextFunction, Request, Response } from "express";
import { env } from "../../config/env.js";
import type { BeeLearntRole } from "../../shared/types/auth.js";
import {
  extractBearerToken,
  parseRole,
  resolveUserFromToken,
} from "../../shared/utils/auth-resolver.js";

/**
 * Main authentication middleware.
 *
 * Strategy order:
 * 1. Better Auth session token (bearer) — calls Next.js Better Auth API
 * 2. Local JWT verification — development/testing fallback
 * 3. Dev headers (x-beelearn-user-id + x-beelearn-role) — local dev only
 *
 * Sets req.user when authentication succeeds. Does NOT reject
 * unauthenticated requests — use `requireAuth` for that.
 */
export async function authenticate(
  req: Request,
  _res: Response,
  next: NextFunction
) {
  const token = extractBearerToken(req.header("authorization"));
  const headerRole = parseRole(req.header("x-beelearn-role"));
  const headerUserId = req.header("x-beelearn-user-id");

  if (token) {
    req.user = (await resolveUserFromToken(token)) ?? undefined;
  } else if (
    headerUserId &&
    headerRole &&
    env.nodeEnv === "development"
  ) {
    // Dev header authentication (development only)
    req.user = { id: headerUserId, role: headerRole };
  }

  next();
}

/**
 * Guard middleware — rejects if req.user is not set.
 */
export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  if (!req.user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  next();
}

/**
 * Guard middleware — rejects if user's role is not in the allowed list.
 */
export function requireRole(allowed: BeeLearntRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !allowed.includes(req.user.role)) {
      res.status(403).json({ message: "Forbidden" });
      return;
    }
    next();
  };
}
