import jwt from "jsonwebtoken";
import { env } from "../../config/env.js";
import {
  getNeonAuthUser,
  syncUserFromNeonAuth,
  verifyNeonAuthSession,
} from "../../modules/auth/neon-auth-sync.js";
import type { AuthUser, BeeLearntRole } from "../types/auth.js";
import { verifyNeonToken } from "./neon-auth.js";

type JwtPayload = {
  id?: string | number;
  userId?: string | number;
  sub?: string | number;
  role?: BeeLearntRole | string;
  email?: string;
  name?: string;
};

const VALID_ROLES: BeeLearntRole[] = ["STUDENT", "PARENT", "ADMIN", "TUTOR"];

export function parseRole(value?: string | null): BeeLearntRole | null {
  if (!value) return null;
  const upper = value.toUpperCase();
  return VALID_ROLES.includes(upper as BeeLearntRole)
    ? (upper as BeeLearntRole)
    : null;
}

export function extractBearerToken(value?: string | null): string | null {
  if (!value) return null;
  if (value.startsWith("Bearer ")) {
    return value.slice("Bearer ".length).trim() || null;
  }
  return value.trim() || null;
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
  payload: Record<string, unknown>,
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

function toAuthUser(input: {
  id: string;
  role: BeeLearntRole;
  email?: string | null;
  name?: string | null;
}): AuthUser {
  return {
    id: input.id,
    role: input.role,
    email: input.email ?? undefined,
    name: input.name ?? undefined,
  };
}

/**
 * Resolve an authenticated user from a bearer/session token.
 *
 * Strategy order:
 * 1. Neon Auth session token verification
 * 2. Neon Auth JWT/access-token verification
 * 3. Local JWT verification (legacy fallback)
 */
export async function resolveUserFromToken(token: string): Promise<AuthUser | null> {
  // 1. Neon Auth session token.
  try {
    const sessionData = await verifyNeonAuthSession(token);
    if (sessionData) {
      const organizationId = sessionData.session.activeOrganizationId ?? null;
      const syncResult = await syncUserFromNeonAuth(
        sessionData.user.id,
        organizationId,
      );
      if (syncResult) {
        return toAuthUser({
          id: sessionData.user.id,
          role: syncResult.role,
          email: sessionData.user.email,
          name: sessionData.user.name,
        });
      }
    }
  } catch {
    // Fall through.
  }

  // 2. Neon Auth access token/JWT.
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
            return toAuthUser({
              id: neonUser.id,
              role: syncResult.role,
              email: neonUser.email,
              name: neonUser.name,
            });
          }
        }
      }
    }
  } catch {
    // Fall through.
  }

  // 3. Local JWT fallback.
  if (env.jwtSecret) {
    try {
      const payload = jwt.verify(token, env.jwtSecret) as JwtPayload;
      const role = parseRole(typeof payload.role === "string" ? payload.role : null);
      const idCandidate = payload.id ?? payload.userId ?? payload.sub;
      if (idCandidate && role) {
        return toAuthUser({
          id: String(idCandidate),
          role,
          email: payload.email,
          name: payload.name,
        });
      }
    } catch {
      return null;
    }
  }

  return null;
}
