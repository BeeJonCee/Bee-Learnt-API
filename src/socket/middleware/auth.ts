import type { Socket } from "socket.io";
import jwt from "jsonwebtoken";
import { env } from "../../config/env.js";
import type { BeeLearntRole } from "../../shared/types/auth.js";
import { verifyNeonAuthSession, syncUserFromNeonAuth, getNeonAuthUser } from "../../services/neon-auth-sync.js";
import { verifyNeonToken } from "../../shared/utils/neon-auth.js";

interface SocketUser {
  id: string;
  role: BeeLearntRole;
  email?: string;
  name?: string;
}

type JwtPayload = {
  id?: string | number;
  role?: BeeLearntRole;
  email?: string;
  name?: string;
};

const roles: BeeLearntRole[] = ["STUDENT", "PARENT", "ADMIN", "TUTOR"];

const parseRole = (value?: string | null): BeeLearntRole | null => {
  if (!value) return null;
  const upper = value.toUpperCase();
  if (roles.includes(upper as BeeLearntRole)) {
    return upper as BeeLearntRole;
  }
  return null;
};

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

const extractOrganizationIdFromClaims = (payload: Record<string, unknown>): string | null => {
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

export async function socketAuthMiddleware(
  socket: Socket,
  next: (err?: Error) => void
): Promise<void> {
  try {
    const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace("Bearer ", "");

    if (!token) {
      // Allow anonymous connections for public features
      socket.data.user = null;
      next();
      return;
    }

    // Try Neon Auth session verification first
    try {
      const sessionData = await verifyNeonAuthSession(token);
      if (sessionData) {
        const organizationId = sessionData.session.activeOrganizationId ?? null;
        const syncResult = await syncUserFromNeonAuth(sessionData.user.id, organizationId);
        if (syncResult) {
          socket.data.user = {
            id: sessionData.user.id,
            role: syncResult.role,
            email: sessionData.user.email,
            name: sessionData.user.name,
          } as SocketUser;
          next();
          return;
        }
      }
    } catch (error) {
      // Fall through to other auth strategies
    }

    // Try Neon token verification
    try {
      const neonPayload = await verifyNeonToken(token);
      if (neonPayload) {
        const neonClaims = neonPayload as Record<string, unknown>;
        const neonUserId = extractUserIdFromClaims(neonClaims);
        const email =
          extractString(neonClaims.email) ?? extractString(neonClaims.email_address);
        if (email && neonUserId) {
          const organizationId = extractOrganizationIdFromClaims(neonClaims);
          const neonUser = await getNeonAuthUser(neonUserId, organizationId);
          if (neonUser) {
            const syncResult = await syncUserFromNeonAuth(neonUserId, organizationId);
            if (syncResult) {
              socket.data.user = {
                id: neonUser.id,
                role: syncResult.role,
                email: neonUser.email,
                name: neonUser.name,
              } as SocketUser;
              next();
              return;
            }
          }
        }
      }
    } catch (error) {
      // Fall through to JWT auth
    }

    // Fallback to JWT auth
    if (env.jwtSecret) {
      try {
        const payload = jwt.verify(token, env.jwtSecret) as JwtPayload;
        if (payload?.id && payload?.role) {
          socket.data.user = {
            id: String(payload.id),
            role: payload.role,
            email: payload.email,
            name: payload.name,
          } as SocketUser;
          next();
          return;
        }
      } catch {
        // Invalid JWT
      }
    }

    // No valid auth found, allow as anonymous
    socket.data.user = null;
    next();
  } catch (error) {
    next(new Error("Authentication failed"));
  }
}
