import type { NextFunction, Request, Response } from "express";
import * as jwt from "jsonwebtoken";
import { env } from "../../config/env.js";
import type { BeeLearntRole } from "../../shared/types/auth.js";
import {
  getNeonAuthUser,
  syncUserFromNeonAuth,
  verifyNeonAuthSession,
} from "../../lib/auth/neon-auth-sync.js";
import { verifyNeonToken } from "../../shared/utils/neon-auth.js";

type JwtPayload = {
  id?: string | number;
  role?: BeeLearntRole;
  email?: string;
  name?: string;
};

const VALID_ROLES: BeeLearntRole[] = ["STUDENT", "PARENT", "ADMIN", "TUTOR"];

function parseRole(value?: string | null): BeeLearntRole | null {
  if (!value) return null;
  const upper = value.toUpperCase();
  return VALID_ROLES.includes(upper as BeeLearntRole)
    ? (upper as BeeLearntRole)
    : null;
}

const extractString = (value: unknown): string | null =>
  typeof value === "string" && value.trim().length > 0 ? value : null;

const extractUserIdFromClaims = (payload: Record<string, unknown>): string | null => {
  const candidates = [
    payload.sub,
    payload.user_id,
    payload.userId,
    payload.id,
    (payload.user_metadata as Record<string, unknown> | undefined)?.id,
    (payload.user_metadata as Record<string, unknown> | undefined)?.user_id,
  ];

  for (const candidate of candidates) {
    const parsed = extractString(candidate);
    if (parsed) return parsed;
  }

  return null;
};

const extractOrganizationIdFromClaims = (
  payload: Record<string, unknown>
): string | null => {
  const session = payload.session as Record<string, unknown> | undefined;
  const organization = payload.organization as Record<string, unknown> | undefined;
  const candidates = [
    payload.activeOrganizationId,
    payload.active_organization_id,
    payload.organizationId,
    payload.organization_id,
    payload.orgId,
    payload.org_id,
    session?.activeOrganizationId,
    session?.active_organization_id,
    organization?.id,
    organization?.organizationId,
  ];

  for (const candidate of candidates) {
    const parsed = extractString(candidate);
    if (parsed) return parsed;
  }

  return null;
};

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
  const authHeader = req.header("authorization");
  const headerRole = parseRole(req.header("x-beelearn-role"));
  const headerUserId = req.header("x-beelearn-user-id");

  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice("Bearer ".length);

    // 1. Try Neon Auth session verification (session token)
    try {
      const sessionData = await verifyNeonAuthSession(token);
      if (sessionData) {
        const organizationId = sessionData.session.activeOrganizationId ?? null;
        const syncResult = await syncUserFromNeonAuth(
          sessionData.user.id,
          organizationId,
        );
        if (syncResult) {
          req.user = {
            id: sessionData.user.id,
            role: syncResult.role,
            email: sessionData.user.email,
            name: sessionData.user.name,
          };
          next();
          return;
        }
      }
    } catch {
      // Fall through to other auth strategies
    }

    // 2. Try Neon Auth JWT verification (access tokens)
    try {
      const neonPayload = await verifyNeonToken(token);
      if (neonPayload) {
        const neonClaims = neonPayload as Record<string, unknown>;
        const neonUserId = extractUserIdFromClaims(neonClaims);
        const email =
          extractString(neonClaims.email) ??
          extractString(neonClaims.email_address);
        if (neonUserId && email) {
          const organizationId = extractOrganizationIdFromClaims(neonClaims);
          const neonUser = await getNeonAuthUser(neonUserId, organizationId);
          if (neonUser) {
            const syncResult = await syncUserFromNeonAuth(
              neonUserId,
              organizationId,
            );
            if (syncResult) {
              req.user = {
                id: neonUser.id,
                role: syncResult.role,
                email: neonUser.email,
                name: neonUser.name,
              };
              next();
              return;
            }
          }
        }
      }
    } catch {
      // Fall through to JWT auth
    }

    // 3. Fallback to local JWT verification
    if (env.jwtSecret) {
      try {
        const payload = jwt.verify(token, env.jwtSecret) as JwtPayload;
        if (payload?.id && payload?.role) {
          req.user = {
            id: String(payload.id),
            role: payload.role,
            email: payload.email,
            name: payload.name,
          };
        }
      } catch {
        req.user = undefined;
      }
    }
  } else if (
    headerUserId &&
    headerRole &&
    env.nodeEnv === "development"
  ) {
    // 3. Dev header authentication (development only)
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
