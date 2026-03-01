import { eq } from "drizzle-orm";
import type { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { env } from "../../config/env.js";
import { db } from "../../core/database/index.js";
import { users } from "../../core/database/schema/users.schema.js";
import { asyncHandler } from "../../core/middleware/async-handler.js";
import { loginUser, registerUser, forgotPassword, resetPassword } from "./auth.service.js";
import { sendLoginAlerts } from "./auth-notifications.service.js";
import {
  normalizeVerificationTarget,
  sendVerificationCode,
  type VerificationChannel,
  verifyVerificationCode,
} from "./auth-verification.service.js";
import {
  sendTwoFactorChallenge,
  verifyTwoFactorCode,
} from "./two-factor.service.js";
import {
  setInitialUserRole,
  syncNeonAuthUserToApp,
  verifyNeonAuthSession,
} from "./neon-auth-sync.js";
import { isDatabaseAuthError } from "../../shared/utils/db-errors.js";
import { verifyNeonToken } from "../../shared/utils/neon-auth.js";
import type { BeeLearntRole } from "../../shared/types/auth.js";
import { logAudit } from "../../shared/audit/audit-log.js";

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

const getRequestMeta = (req: Request) => ({
  method: req.method,
  path: req.originalUrl,
  ip: req.ip,
});

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const extractClientIp = (req: Request): string | null => {
  const forwardedFor = extractString(req.header("x-forwarded-for"));
  if (forwardedFor) {
    const [firstIp] = forwardedFor.split(",");
    return firstIp?.trim() ?? null;
  }

  return req.ip ?? null;
};

const SELF_SIGNUP_ROLES: BeeLearntRole[] = ["STUDENT", "PARENT"];

const parseDesiredSignupRole = (value: unknown): BeeLearntRole | null => {
  const parsed = extractString(value)?.toUpperCase();
  if (!parsed) return null;

  const role = parsed as BeeLearntRole;
  return SELF_SIGNUP_ROLES.includes(role) ? role : null;
};

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

export const register = asyncHandler(async (req: Request, res: Response) => {
  const traceId = getTraceId(req, "register");
  const requestMeta = getRequestMeta(req);
  res.setHeader("x-auth-trace-id", traceId);

  const body = req.body as { email?: unknown };
  const email = extractString(body.email);

  console.info(`${AUTH_API_LOG_NS} register:start`, {
    traceId,
    email: maskEmail(email),
    ...requestMeta,
  });

  try {
    const result = await registerUser(req.body);

    let emailDelivery = false;
    let smsDelivery = false;
    const channels: VerificationChannel[] = ["email"];

    try {
      await sendVerificationCode({
        userId: result.id,
        channel: "email",
        purpose: "email_verification",
        target: result.email,
      });
      emailDelivery = true;
    } catch (error) {
      console.warn(`${AUTH_API_LOG_NS} register:email-verification-send-failed`, {
        traceId,
        userId: result.id,
        message: getErrorMessage(error),
      });
    }

    if (result.phone) {
      channels.push("sms");
      try {
        await sendVerificationCode({
          userId: result.id,
          channel: "sms",
          purpose: "phone_verification",
          target: result.phone,
        });
        smsDelivery = true;
      } catch (error) {
        console.warn(`${AUTH_API_LOG_NS} register:sms-verification-send-failed`, {
          traceId,
          userId: result.id,
          message: getErrorMessage(error),
        });
      }
    }

    await logAudit({
      actorId: result.id,
      action: "auth.register",
      entity: "user",
      details: {
        role: result.role,
        email: maskEmail(result.email),
        emailDelivery,
        smsDelivery,
      },
      req,
    });

    console.info(`${AUTH_API_LOG_NS} register:success`, {
      traceId,
      userId: result.id,
      role: result.role,
      emailDelivery,
      smsDelivery,
      ...requestMeta,
    });

    res.status(201).json({
      userId: result.id,
      verificationRequired: true,
      channels,
      emailDelivery,
      smsDelivery,
      message: emailDelivery
        ? "Verification code sent. Please verify your email to activate your account."
        : "Account created. Use resend verification to receive your code.",
    });
  } catch (error) {
    console.error(`${AUTH_API_LOG_NS} register:error`, {
      traceId,
      message: getErrorMessage(error),
      ...requestMeta,
    });
    if (isDatabaseAuthError(error)) {
      res.status(503).json({
        message:
          "Authentication service is temporarily unavailable. Please try again later.",
      });
      return;
    }
    throw error;
  }
});

export const login = asyncHandler(async (req: Request, res: Response) => {
  const traceId = getTraceId(req, "login");
  const requestMeta = getRequestMeta(req);
  res.setHeader("x-auth-trace-id", traceId);

  const body = req.body as { email?: unknown };
  const email = extractString(body.email);

  console.info(`${AUTH_API_LOG_NS} login:start`, {
    traceId,
    email: maskEmail(email),
    ...requestMeta,
  });

  try {
    const result = await loginUser(req.body);

    if (result.requiresVerification) {
      await logAudit({
        actorId: result.user.id,
        action: "login_failed",
        entity: "user",
        details: { reason: "email_unverified" },
        req,
      });

      res.status(403).json({
        message: "Verify your email to continue.",
        verificationRequired: true,
        channels: result.channels,
        target: result.user.email,
        ...(result.user.phone ? { smsTarget: result.user.phone } : {}),
      });
      return;
    }

    const alertsSent = await sendLoginAlerts({
      userId: result.user.id,
      email: result.user.email,
      phone: result.user.phone,
      loginEmailAlertEnabled: result.alertPreferences.loginEmailAlertEnabled,
      loginSmsAlertEnabled: result.alertPreferences.loginSmsAlertEnabled,
      meta: {
        ipAddress: extractClientIp(req),
        userAgent: extractString(req.header("user-agent")),
      },
    });

    await logAudit({
      actorId: result.user.id,
      action: "login_success",
      entity: "user",
      details: {
        role: result.user.role,
        alertsSent,
      },
      req,
    });

    console.info(`${AUTH_API_LOG_NS} login:success`, {
      traceId,
      userId: result.user.id,
      role: result.user.role,
      ...requestMeta,
    });

    res.json({
      token: result.token,
      user: {
        id: result.user.id,
        name: result.user.name,
        email: result.user.email,
        role: result.user.role,
      },
      alertsSent,
    });
  } catch (error) {
    console.error(`${AUTH_API_LOG_NS} login:error`, {
      traceId,
      message: getErrorMessage(error),
      ...requestMeta,
    });
    if (isDatabaseAuthError(error)) {
      res.status(503).json({
        message:
          "Authentication service is temporarily unavailable. Please try again later.",
      });
      return;
    }
    throw error;
  }
});

export const sendVerificationCodeHandler = asyncHandler(
  async (req: Request, res: Response) => {
    const traceId = getTraceId(req, "verification-send");
    const requestMeta = getRequestMeta(req);

    const body = req.body as {
      channel: VerificationChannel;
      target: string;
      purpose?: "email_verification" | "phone_verification";
    };

    const channel = body.channel;
    const rawTarget = extractString(body.target);

    if (!rawTarget) {
      res.status(400).json({ message: "target is required" });
      return;
    }

    const normalizedTarget = normalizeVerificationTarget(channel, rawTarget);

    const [user] = await db
      .select({
        id: users.id,
        emailVerifiedAt: users.emailVerifiedAt,
        phoneVerifiedAt: users.phoneVerifiedAt,
      })
      .from(users)
      .where(
        channel === "email"
          ? eq(users.email, normalizedTarget)
          : eq(users.phone, normalizedTarget),
      )
      .limit(1);

    if (!user) {
      await sleep(250);
      res.json({ ok: true, cooldownSeconds: 60 });
      return;
    }

    await logAudit({
      actorId: user.id,
      action: "resend_requested",
      entity: "user",
      details: { channel },
      req,
    });

    if (
      (channel === "email" && user.emailVerifiedAt) ||
      (channel === "sms" && user.phoneVerifiedAt)
    ) {
      res.json({ ok: true, cooldownSeconds: 60 });
      return;
    }

    try {
      const verification = await sendVerificationCode({
        userId: user.id,
        channel,
        purpose:
          body.purpose ??
          (channel === "email" ? "email_verification" : "phone_verification"),
        target: normalizedTarget,
      });

      console.info(`${AUTH_API_LOG_NS} verification:send:success`, {
        traceId,
        userId: user.id,
        channel,
        ...requestMeta,
      });

      res.json({
        ok: true,
        cooldownSeconds: verification.cooldownSeconds,
        expiresInSeconds: verification.expiresInSeconds,
      });
    } catch (error) {
      console.warn(`${AUTH_API_LOG_NS} verification:send:failed`, {
        traceId,
        userId: user.id,
        channel,
        message: getErrorMessage(error),
      });

      // Generic success response avoids account enumeration.
      res.json({ ok: true, cooldownSeconds: 60 });
    }
  },
);

export const verifyVerificationCodeHandler = asyncHandler(
  async (req: Request, res: Response) => {
    const body = req.body as {
      channel: VerificationChannel;
      target: string;
      code: string;
    };

    const normalizedTarget = normalizeVerificationTarget(
      body.channel,
      body.target,
    );

    const result = await verifyVerificationCode({
      channel: body.channel,
      target: normalizedTarget,
      code: body.code,
    });

    if (!result.valid) {
      res.status(400).json({
        verified: false,
        message: "Invalid or expired verification code.",
      });
      return;
    }

    if (result.userId) {
      if (body.channel === "email") {
        await db
          .update(users)
          .set({ emailVerifiedAt: new Date() })
          .where(eq(users.id, result.userId));
      } else {
        await db
          .update(users)
          .set({ phoneVerifiedAt: new Date() })
          .where(eq(users.id, result.userId));
      }
    }

    res.json({ verified: true });
  },
);

export const getAuthPreferences = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const [user] = await db
    .select({
      email: users.email,
      phone: users.phone,
      emailVerifiedAt: users.emailVerifiedAt,
      phoneVerifiedAt: users.phoneVerifiedAt,
      loginEmailAlertEnabled: users.loginEmailAlertEnabled,
      loginSmsAlertEnabled: users.loginSmsAlertEnabled,
    })
    .from(users)
    .where(eq(users.id, req.user.id))
    .limit(1);

  if (!user) {
    res.status(404).json({ message: "User not found" });
    return;
  }

  res.json({
    email: user.email,
    phone: user.phone,
    emailVerifiedAt: user.emailVerifiedAt,
    phoneVerifiedAt: user.phoneVerifiedAt,
    loginEmailAlertEnabled: user.loginEmailAlertEnabled,
    loginSmsAlertEnabled: user.loginSmsAlertEnabled,
  });
});

export const patchAuthPreferences = asyncHandler(
  async (req: Request, res: Response) => {
    if (!req.user) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const body = req.body as {
      loginEmailAlertEnabled?: boolean;
      loginSmsAlertEnabled?: boolean;
    };

    const [user] = await db
      .select({
        phone: users.phone,
        phoneVerifiedAt: users.phoneVerifiedAt,
      })
      .from(users)
      .where(eq(users.id, req.user.id))
      .limit(1);

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    if (body.loginSmsAlertEnabled === true && (!user.phone || !user.phoneVerifiedAt)) {
      res.status(400).json({
        message:
          "Verify a phone number before enabling SMS login alerts.",
      });
      return;
    }

    await db
      .update(users)
      .set({
        ...(body.loginEmailAlertEnabled !== undefined
          ? { loginEmailAlertEnabled: body.loginEmailAlertEnabled }
          : {}),
        ...(body.loginSmsAlertEnabled !== undefined
          ? { loginSmsAlertEnabled: body.loginSmsAlertEnabled }
          : {}),
      })
      .where(eq(users.id, req.user.id));

    const [updated] = await db
      .select({
        email: users.email,
        phone: users.phone,
        emailVerifiedAt: users.emailVerifiedAt,
        phoneVerifiedAt: users.phoneVerifiedAt,
        loginEmailAlertEnabled: users.loginEmailAlertEnabled,
        loginSmsAlertEnabled: users.loginSmsAlertEnabled,
      })
      .from(users)
      .where(eq(users.id, req.user.id))
      .limit(1);

    res.json(updated);
  },
);
export const me = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  res.json({ user: req.user });
});

export const updateMe = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const { name } = req.body as { name?: string };
  if (!name || typeof name !== "string" || name.trim().length === 0) {
    res.status(400).json({ message: "Name is required" });
    return;
  }

  const trimmedName = name.trim();
  if (trimmedName.length > 120) {
    res.status(400).json({ message: "Name must be 120 characters or fewer" });
    return;
  }

  await db
    .update(users)
    .set({ name: trimmedName })
    .where(eq(users.id, req.user.id));

  res.json({
    user: {
      ...req.user,
      name: trimmedName,
    },
  });
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
  const requestMeta = getRequestMeta(req);
  res.setHeader("x-auth-trace-id", traceId);

  const { sessionToken, desiredRole, twoFactorCode } = req.body as {
    sessionToken: string;
    desiredRole?: unknown;
    twoFactorCode?: unknown;
  };
  const normalizedTwoFactorCode = extractString(twoFactorCode);
  const normalizedDesiredRole = parseDesiredSignupRole(desiredRole);

  if (desiredRole !== undefined && !normalizedDesiredRole) {
    console.warn(`${AUTH_API_LOG_NS} exchange:invalid-desired-role`, {
      traceId,
      desiredRole,
      ...requestMeta,
    });
    res.status(400).json({ message: "desiredRole must be STUDENT or PARENT" });
    return;
  }

  console.info(`${AUTH_API_LOG_NS} exchange:start`, {
    traceId,
    hasSessionToken: Boolean(sessionToken),
    sessionTokenLength: typeof sessionToken === "string" ? sessionToken.length : 0,
    desiredRole: normalizedDesiredRole,
    ...requestMeta,
  });

  if (!sessionToken) {
    console.warn(`${AUTH_API_LOG_NS} exchange:missing-session-token`, {
      traceId,
      ...requestMeta,
    });
    res.status(400).json({ message: "Missing sessionToken" });
    return;
  }

  if (!env.jwtSecret) {
    console.error(`${AUTH_API_LOG_NS} exchange:missing-jwt-secret`, {
      traceId,
      ...requestMeta,
    });
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
      ...requestMeta,
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
        ...requestMeta,
      });
    }
  }

  if (!neonUserId) {
    console.warn(`${AUTH_API_LOG_NS} exchange:invalid-token`, {
      traceId,
      ...requestMeta,
    });
    res.status(401).json({ message: "Invalid token" });
    return;
  }

  if (normalizedDesiredRole) {
    try {
      await setInitialUserRole(neonUserId, normalizedDesiredRole);
      console.info(`${AUTH_API_LOG_NS} exchange:role-applied`, {
        traceId,
        neonUserId,
        desiredRole: normalizedDesiredRole,
      });
    } catch (error) {
      console.error(`${AUTH_API_LOG_NS} exchange:role-apply-failed`, {
        traceId,
        neonUserId,
        desiredRole: normalizedDesiredRole,
        message: getErrorMessage(error),
        ...requestMeta,
      });
      res.status(400).json({ message: "Failed to apply requested role" });
      return;
    }
  }

  const syncResult = await syncNeonAuthUserToApp(neonUserId, organizationId);
  if (!syncResult) {
    console.error(`${AUTH_API_LOG_NS} exchange:sync-failed`, {
      traceId,
      neonUserId,
      organizationId,
      ...requestMeta,
    });
    res.status(400).json({ message: "Failed to sync user from Neon Auth" });
    return;
  }

  if (!normalizedTwoFactorCode) {
    const challenge = await sendTwoFactorChallenge({
      email: syncResult.email,
      purpose: "social",
    });
    console.info(`${AUTH_API_LOG_NS} exchange:two-factor:challenge-sent`, {
      traceId,
      userId: syncResult.id,
      email: maskEmail(syncResult.email),
      ...requestMeta,
    });
    res.status(202).json(challenge);
    return;
  }

  const verification = await verifyTwoFactorCode({
    email: syncResult.email,
    code: normalizedTwoFactorCode,
  });

  if (!verification.valid) {
    console.warn(`${AUTH_API_LOG_NS} exchange:two-factor:invalid-code`, {
      traceId,
      userId: syncResult.id,
      email: maskEmail(syncResult.email),
      ...requestMeta,
    });
    res
      .status(401)
      .json({ message: "Invalid or expired verification code. Please try again." });
    return;
  }

  const token = issueBackendJwt({
    id: syncResult.id,
    name: syncResult.name,
    email: syncResult.email,
    role: syncResult.role,
  });

  if (!token) {
    console.error(`${AUTH_API_LOG_NS} exchange:jwt-issue-failed`, {
      traceId,
      ...requestMeta,
    });
    res.status(500).json({ message: "JWT secret is not configured" });
    return;
  }

  console.info(`${AUTH_API_LOG_NS} exchange:success`, {
    traceId,
    userId: syncResult.id,
    role: syncResult.role,
    ...requestMeta,
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

/**
 * POST /api/auth/forgot-password
 * Send a password-reset link. Always responds 200 to prevent email enumeration.
 */
export const forgotPasswordHandler = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body as { email: string };

  try {
    await forgotPassword(email);
  } catch (error) {
    // Log 503 (SMTP unavailable) but still return a generic 200 to the client.
    // Re-throw any unexpected error.
    if (!(error instanceof Error && error.message.includes("Failed to send"))) {
      throw error;
    }
    console.warn(`${AUTH_API_LOG_NS} forgot-password:smtp-unavailable`);
  }

  res.json({
    message: "If that email is registered you will receive a reset link shortly.",
  });
});

/**
 * POST /api/auth/reset-password
 * Complete a password reset using the token from the email link.
 */
export const resetPasswordHandler = asyncHandler(async (req: Request, res: Response) => {
  const { token, newPassword } = req.body as { token: string; newPassword: string };

  await resetPassword(token, newPassword);

  res.json({ message: "Password updated successfully. You can now log in." });
});

