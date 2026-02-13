import type { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { env } from "../config/env.js";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { loginUser } from "../services/auth.service.js";
import {
  syncNeonAuthUserToApp,
  verifyNeonAuthSession,
} from "../services/neon-auth-sync.js";
import { verifyNeonToken } from "../shared/utils/neon-auth.js";

const AUTH_API_LOG_NS = "[auth-api]";

const extractString = (value: unknown): string | null =>
  typeof value === "string" && value.trim().length > 0 ? value : null;

const maskEmail = (email: string | null) => {
  if (!email) return "***";
  const parts = email.split("@");
  if (parts.length !== 2) return "***";
  const [local, domain] = parts;
  if (local.length <= 2) return `***@${domain}`;
  return `${local.slice(0, 2)}***@${domain}`;
};

const getErrorMessage = (error: unknown) =>
  error instanceof Error ? error.message : "Unknown error";

const createTraceId = (action: string) =>
  `${action}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

const getTraceId = (req: Request, action: string) =>
  extractString(req.header("x-auth-trace-id")) ?? createTraceId(action);

const extractNeonUserIdFromClaims = (
  payload: Record<string, unknown>,
): string | null => {
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

const issueBackendJwt = (input: {
  id: string;
  name: string | null;
  email: string;
  role: string;
}) => {
  if (!env.jwtSecret) return null;

  return jwt.sign(
    {
      id: input.id,
      role: input.role,
      email: input.email,
      name: input.name,
    },
    env.jwtSecret,
    { expiresIn: "7d" },
  );
};

export const login = asyncHandler(async (req: Request, res: Response) => {
  const traceId = getTraceId(req, "login");
  res.setHeader("x-auth-trace-id", traceId);

  const email = extractString((req.body as { email?: unknown })?.email);
  console.info(`${AUTH_API_LOG_NS} login:start`, {
    traceId,
    email: maskEmail(email),
    ip: req.ip,
  });

  try {
    const result = await loginUser(req.body);
    console.info(`${AUTH_API_LOG_NS} login:success`, {
      traceId,
      userId: result.user.id,
      role: result.user.role,
    });
    res.json(result);
  } catch (error) {
    console.error(`${AUTH_API_LOG_NS} login:error`, {
      traceId,
      message: getErrorMessage(error),
    });
    throw error;
  }
});

export const me = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  res.json({ user: req.user });
});

export const socialBridge = asyncHandler(async (req: Request, res: Response) => {
  if (!env.jwtSecret) {
    res.status(500).json({ message: "JWT secret is not configured" });
    return;
  }

  const internalSecret = req.header("x-internal-secret");
  if (!internalSecret || internalSecret !== env.jwtSecret) {
    res.status(403).json({ message: "Forbidden" });
    return;
  }

  const { neonAuthUserId } = req.body as { neonAuthUserId: string };
  if (!neonAuthUserId) {
    res.status(400).json({ message: "neonAuthUserId is required" });
    return;
  }

  const syncResult = await syncNeonAuthUserToApp(neonAuthUserId);
  if (!syncResult) {
    res.status(400).json({ message: "Failed to sync user from Neon Auth" });
    return;
  }

  const token = issueBackendJwt({
    id: syncResult.id,
    name: syncResult.name,
    email: syncResult.email,
    role: syncResult.role,
  });

  if (!token) {
    res.status(500).json({ message: "JWT secret is not configured" });
    return;
  }

  res.json({
    token,
    user: {
      id: syncResult.id,
      name: syncResult.name,
      email: syncResult.email,
      role: syncResult.role,
    },
  });
});

/**
 * Exchange Neon Auth token (session token or access token) for backend JWT.
 */
export const exchangeNeonToken = asyncHandler(async (req: Request, res: Response) => {
  const traceId = getTraceId(req, "exchange-neon-token");
  res.setHeader("x-auth-trace-id", traceId);

  const { sessionToken } = req.body as { sessionToken: string };
  console.info(`${AUTH_API_LOG_NS} exchange:start`, {
    traceId,
    hasSessionToken: Boolean(sessionToken),
    sessionTokenLength: typeof sessionToken === "string" ? sessionToken.length : 0,
    ip: req.ip,
  });

  if (!sessionToken) {
    console.warn(`${AUTH_API_LOG_NS} exchange:missing-session-token`, { traceId });
    res.status(400).json({ message: "Missing sessionToken" });
    return;
  }

  if (!env.jwtSecret) {
    console.error(`${AUTH_API_LOG_NS} exchange:missing-jwt-secret`, { traceId });
    res.status(500).json({ message: "JWT secret is not configured" });
    return;
  }

  let neonUserId: string | null = null;
  let organizationId: string | null = null;

  // 1) Session token path (primary for Better Auth cookie tokens).
  try {
    const sessionData = await verifyNeonAuthSession(sessionToken);
    if (sessionData?.user?.id) {
      neonUserId = sessionData.user.id;
      organizationId = sessionData.session.activeOrganizationId ?? null;
      console.info(`${AUTH_API_LOG_NS} exchange:session-verified`, {
        traceId,
        neonUserId,
        organizationId,
      });
    }
  } catch (error) {
    console.warn(`${AUTH_API_LOG_NS} exchange:session-verify-error`, {
      traceId,
      message: getErrorMessage(error),
    });
  }

  // 2) Access token path (JWT signed by Neon Auth).
  if (!neonUserId) {
    try {
      const neonPayload = await verifyNeonToken(sessionToken);
      if (neonPayload) {
        const claims = neonPayload as Record<string, unknown>;
        const exp = claims.exp;

        if (typeof exp === "number" && exp * 1000 < Date.now()) {
          console.warn(`${AUTH_API_LOG_NS} exchange:token-expired`, { traceId });
          res.status(401).json({ message: "Token expired" });
          return;
        }

        neonUserId = extractNeonUserIdFromClaims(claims);
        organizationId = extractOrganizationIdFromClaims(claims);
        console.info(`${AUTH_API_LOG_NS} exchange:jwt-verified`, {
          traceId,
          neonUserId,
          organizationId,
        });
      }
    } catch (error) {
      console.warn(`${AUTH_API_LOG_NS} exchange:jwt-verify-error`, {
        traceId,
        message: getErrorMessage(error),
      });
    }
  }

  if (!neonUserId) {
    console.warn(`${AUTH_API_LOG_NS} exchange:invalid-token`, { traceId });
    res.status(401).json({ message: "Invalid token" });
    return;
  }

  const syncResult = await syncNeonAuthUserToApp(neonUserId, organizationId);
  if (!syncResult) {
    console.error(`${AUTH_API_LOG_NS} exchange:sync-failed`, {
      traceId,
      neonUserId,
      organizationId,
    });
    res.status(400).json({ message: "Failed to sync user from Neon Auth" });
    return;
  }

  const token = issueBackendJwt({
    id: syncResult.id,
    name: syncResult.name,
    email: syncResult.email,
    role: syncResult.role,
  });

  if (!token) {
    console.error(`${AUTH_API_LOG_NS} exchange:jwt-issue-failed`, { traceId });
    res.status(500).json({ message: "JWT secret is not configured" });
    return;
  }

  console.info(`${AUTH_API_LOG_NS} exchange:success`, {
    traceId,
    userId: syncResult.id,
    role: syncResult.role,
  });

  res.json({
    token,
    user: {
      id: syncResult.id,
      name: syncResult.name,
      email: syncResult.email,
      role: syncResult.role,
    },
  });
});
