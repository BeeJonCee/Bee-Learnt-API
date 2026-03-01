/**
 * Auth Service
 *
 * Neon Auth is the sole identity provider.
 * This service handles legacy email/password login (for existing local users)
 * and Neon Auth credential login as a fallback.
 *
 * Registration is primarily handled by Neon Auth SDK on the frontend.
 * A local register fallback is also supported when Neon Auth endpoints are unavailable.
 */

import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { and, eq, gt, isNull, or } from "drizzle-orm";
import { randomUUID } from "crypto";
import { db } from "../../core/database/index.js";
import { roles, users, passwordResetTokens } from "../../core/database/schema/index.js";
import { env } from "../../config/env.js";
import { HttpError } from "../../shared/utils/http-error.js";
import type { BeeLearntRole } from "../../shared/types/auth.js";
import type { VerificationChannel } from "./auth-verification.service.js";
import {
  isNeonAuthAvailable,
  authenticateViaNeonAuth,
} from "./neon-auth-sync.js";
import {
  syncPasswordToNeonAuth,
  syncToNeonAuthUser,
} from "../../shared/utils/schema-sync.js";
import { sendPasswordResetEmail } from "../../shared/email/send-two-factor.js";
import { isE164Phone, normalizeSAPhone } from "../../shared/utils/phone.js";

type LoginInput = {
  /** email address or E.164 phone number (+27821234567) */
  email: string;
  password: string;
};

type RegisterInput = {
  name: string;
  email: string;
  password: string;
  phone?: string;
  role: BeeLearntRole;
};

export type RegisterUserResult = {
  id: string;
  name: string;
  email: string;
  phone: string | null;
  role: BeeLearntRole;
};

type LoginBaseUser = {
  id: string;
  name: string;
  email: string;
  role: BeeLearntRole;
  phone: string | null;
};

type LoginSuccessResult = {
  requiresVerification: false;
  token: string;
  user: LoginBaseUser;
  alertPreferences: {
    loginEmailAlertEnabled: boolean;
    loginSmsAlertEnabled: boolean;
  };
};

type LoginVerificationRequiredResult = {
  requiresVerification: true;
  user: LoginBaseUser;
  channels: VerificationChannel[];
};

export type LoginUserResult = LoginSuccessResult | LoginVerificationRequiredResult;

const AUTH_SERVICE_LOG_NS = "[auth-service]";

function maskEmail(email: string) {
  const parts = email.split("@");
  if (parts.length !== 2) return "***";
  const [local, domain] = parts;
  if (local.length <= 2) return `***@${domain}`;
  return `${local.slice(0, 2)}***@${domain}`;
}

function normalizeRole(role: string): BeeLearntRole {
  return role.toUpperCase() as BeeLearntRole;
}

const NEON_AUTH_OPTIONAL_MISSING_CODES = new Set(["42P01", "3F000"]);

function isNeonOptionalSyncError(error: unknown): boolean {
  const code = (error as { code?: string } | null)?.code;
  return !!code && NEON_AUTH_OPTIONAL_MISSING_CODES.has(code);
}

export async function registerUser(input: RegisterInput): Promise<RegisterUserResult> {
  const normalizedEmail = input.email.trim().toLowerCase();
  const normalizedPhone = input.phone?.trim()
    ? normalizeSAPhone(input.phone.trim())
    : null;
  const normalizedRole = normalizeRole(input.role);
  const maskedEmail = maskEmail(normalizedEmail);

  if (normalizedPhone && !isE164Phone(normalizedPhone)) {
    throw new HttpError("Phone must be E.164 format, e.g. +27821234567", 400);
  }

  console.info(`${AUTH_SERVICE_LOG_NS} register:start`, {
    email: maskedEmail,
    role: normalizedRole,
  });

  const [existingUser] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.email, normalizedEmail))
    .limit(1);

  if (existingUser) {
    console.warn(`${AUTH_SERVICE_LOG_NS} register:email-exists`, {
      email: maskedEmail,
      existingUserId: existingUser.id,
    });
    throw new HttpError("Email already in use.", 409);
  }

  if (normalizedPhone) {
    const [existingPhoneUser] = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.phone, normalizedPhone))
      .limit(1);

    if (existingPhoneUser) {
      console.warn(`${AUTH_SERVICE_LOG_NS} register:phone-exists`, {
        email: maskedEmail,
        existingUserId: existingPhoneUser.id,
      });
      throw new HttpError("Phone number already in use.", 409);
    }
  }

  const [roleRow] = await db
    .select({ id: roles.id, name: roles.name })
    .from(roles)
    .where(eq(roles.name, normalizedRole))
    .limit(1);

  if (!roleRow) {
    console.warn(`${AUTH_SERVICE_LOG_NS} register:role-not-found`, {
      email: maskedEmail,
      role: normalizedRole,
    });
    throw new HttpError("Role not found.", 400);
  }

  const userId = randomUUID();
  const passwordHash = await bcrypt.hash(input.password, 10);

  const [createdUser] = await db
    .insert(users)
    .values({
      id: userId,
      name: input.name.trim(),
      email: normalizedEmail,
      phone: normalizedPhone,
      passwordHash,
      roleId: roleRow.id,
    })
    .returning({
      id: users.id,
      name: users.name,
      email: users.email,
      phone: users.phone,
    });

  // Keep local registration independent from Neon Auth availability.
  try {
    await syncToNeonAuthUser({
      id: userId,
      name: createdUser.name,
      email: createdUser.email,
      role: normalizedRole,
      image: null,
    });

    await syncPasswordToNeonAuth({
      userId,
      email: createdUser.email,
      passwordHash,
    });

    console.info(`${AUTH_SERVICE_LOG_NS} register:neon-sync:success`, {
      email: maskedEmail,
      userId,
    });
  } catch (error) {
    if (isNeonOptionalSyncError(error)) {
      console.warn(`${AUTH_SERVICE_LOG_NS} register:neon-sync:skipped`, {
        email: maskedEmail,
        userId,
        reason: "Neon Auth tables/configuration unavailable",
      });
    } else {
      console.warn(`${AUTH_SERVICE_LOG_NS} register:neon-sync:error`, {
        email: maskedEmail,
        userId,
        message: error instanceof Error ? error.message : "Unknown sync error",
      });
    }
  }

  console.info(`${AUTH_SERVICE_LOG_NS} register:success`, {
    email: maskedEmail,
    userId,
    role: normalizedRole,
  });

  return {
    id: createdUser.id,
    name: createdUser.name,
    email: createdUser.email,
    phone: createdUser.phone ?? null,
    role: normalizedRole,
  };
}

export async function loginUser(input: LoginInput): Promise<LoginUserResult> {
  const maskedEmail = maskEmail(input.email);
  console.info(`${AUTH_SERVICE_LOG_NS} login:start`, { email: maskedEmail });

  if (!env.jwtSecret) {
    console.error(`${AUTH_SERVICE_LOG_NS} login:missing-jwt-secret`, {
      email: maskedEmail,
    });
    throw new HttpError("JWT secret is not configured.", 500);
  }

  const identifier = input.email.trim().toLowerCase();
  const [localUser] = await db
    .select({
      id: users.id,
      name: users.name,
      email: users.email,
      phone: users.phone,
      passwordHash: users.passwordHash,
      role: roles.name,
      emailVerifiedAt: users.emailVerifiedAt,
      lastLoginAt: users.lastLoginAt,
      loginEmailAlertEnabled: users.loginEmailAlertEnabled,
      loginSmsAlertEnabled: users.loginSmsAlertEnabled,
    })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id))
    .where(or(eq(users.email, identifier), eq(users.phone, identifier)));

  const makeVerificationChannels = (phone: string | null): VerificationChannel[] => {
    return phone ? ["email", "sms"] : ["email"];
  };

  if (localUser?.passwordHash) {
    const valid = await bcrypt.compare(input.password, localUser.passwordHash);
    if (!valid) {
      console.warn(`${AUTH_SERVICE_LOG_NS} login:local-password-mismatch`, {
        email: maskedEmail,
        userId: localUser.id,
      });
      throw new HttpError("Invalid email or password.", 401);
    }

    const normalizedRole = localUser.role.toUpperCase() as BeeLearntRole;
    const userBase = {
      id: localUser.id,
      name: localUser.name,
      email: localUser.email,
      role: normalizedRole,
      phone: localUser.phone ?? null,
    };

    const requiresEmailVerification =
      !localUser.emailVerifiedAt &&
      (env.authEnforceEmailVerification || !localUser.lastLoginAt);

    if (requiresEmailVerification) {
      return {
        requiresVerification: true,
        user: userBase,
        channels: makeVerificationChannels(localUser.phone ?? null),
      };
    }

    const token = jwt.sign(
      {
        id: localUser.id,
        role: normalizedRole,
        email: localUser.email,
        name: localUser.name,
      },
      env.jwtSecret,
      { expiresIn: "7d" },
    );

    await db
      .update(users)
      .set({ lastLoginAt: new Date() })
      .where(eq(users.id, localUser.id));

    console.info(`${AUTH_SERVICE_LOG_NS} login:local-success`, {
      email: maskedEmail,
      userId: localUser.id,
      role: normalizedRole,
    });

    return {
      requiresVerification: false,
      token,
      user: userBase,
      alertPreferences: {
        loginEmailAlertEnabled: localUser.loginEmailAlertEnabled,
        loginSmsAlertEnabled: localUser.loginSmsAlertEnabled,
      },
    };
  }

  if (isNeonAuthAvailable()) {
    console.info(`${AUTH_SERVICE_LOG_NS} login:neon-fallback:start`, {
      email: maskedEmail,
    });

    const neonResult = await authenticateViaNeonAuth(input.email, input.password);
    if (neonResult) {
      const [syncedUser] = await db
        .select({
          id: users.id,
          phone: users.phone,
          emailVerifiedAt: users.emailVerifiedAt,
          lastLoginAt: users.lastLoginAt,
          loginEmailAlertEnabled: users.loginEmailAlertEnabled,
          loginSmsAlertEnabled: users.loginSmsAlertEnabled,
        })
        .from(users)
        .where(eq(users.id, neonResult.id))
        .limit(1);

      const requiresEmailVerification =
        !syncedUser?.emailVerifiedAt &&
        (env.authEnforceEmailVerification || !syncedUser?.lastLoginAt);

      if (requiresEmailVerification) {
        return {
          requiresVerification: true,
          user: {
            id: neonResult.id,
            name: neonResult.name,
            email: neonResult.email,
            role: neonResult.role,
            phone: syncedUser?.phone ?? null,
          },
          channels: makeVerificationChannels(syncedUser?.phone ?? null),
        };
      }

      const token = jwt.sign(
        {
          id: neonResult.id,
          role: neonResult.role,
          email: neonResult.email,
          name: neonResult.name,
        },
        env.jwtSecret,
        { expiresIn: "7d" },
      );

      await db
        .update(users)
        .set({ lastLoginAt: new Date() })
        .where(eq(users.id, neonResult.id));

      console.info(`${AUTH_SERVICE_LOG_NS} login:neon-fallback:success`, {
        email: maskedEmail,
        userId: neonResult.id,
        role: neonResult.role,
      });

      return {
        requiresVerification: false,
        token,
        user: {
          id: neonResult.id,
          name: neonResult.name,
          email: neonResult.email,
          role: neonResult.role,
          phone: syncedUser?.phone ?? null,
        },
        alertPreferences: {
          loginEmailAlertEnabled: syncedUser?.loginEmailAlertEnabled ?? true,
          loginSmsAlertEnabled: syncedUser?.loginSmsAlertEnabled ?? false,
        },
      };
    }

    console.warn(`${AUTH_SERVICE_LOG_NS} login:neon-fallback:failed`, {
      email: maskedEmail,
    });
  } else {
    console.warn(`${AUTH_SERVICE_LOG_NS} login:neon-unavailable`, {
      email: maskedEmail,
    });
  }

  console.warn(`${AUTH_SERVICE_LOG_NS} login:failed`, { email: maskedEmail });
  throw new HttpError("Invalid email or password.", 401);
}

const RESET_TOKEN_EXPIRY_MINUTES = 60;
const RESET_TOKEN_LOG_NS = "[auth-service:password-reset]";

function generateResetToken(): { token: string; tokenHash: string } {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  return { token, tokenHash };
}

/**
 * Request a password reset. Always returns a generic success to avoid email enumeration.
 * If the email belongs to an existing user the reset link is sent.
 */
export async function forgotPassword(email: string): Promise<void> {
  const normalizedEmail = email.trim().toLowerCase();

  const [user] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.email, normalizedEmail))
    .limit(1);

  if (!user) {
    // Silent – do not reveal whether the email is registered
    console.info(`${RESET_TOKEN_LOG_NS} forgot:email-not-found`, {
      email: maskEmail(normalizedEmail),
    });
    return;
  }

  const { token, tokenHash } = generateResetToken();
  const expiresAt = new Date(Date.now() + RESET_TOKEN_EXPIRY_MINUTES * 60_000);

  await db.insert(passwordResetTokens).values({
    userId: user.id,
    tokenHash,
    expiresAt,
  });

  const resetUrl = `${env.appUrl}/reset-password?token=${token}`;

  try {
    await sendPasswordResetEmail({
      toEmail: normalizedEmail,
      resetUrl,
      expiresInMinutes: RESET_TOKEN_EXPIRY_MINUTES,
    });
    console.info(`${RESET_TOKEN_LOG_NS} forgot:email-sent`, {
      email: maskEmail(normalizedEmail),
      userId: user.id,
    });
  } catch (error) {
    console.error(`${RESET_TOKEN_LOG_NS} forgot:email-send-failed`, {
      email: maskEmail(normalizedEmail),
      message: error instanceof Error ? error.message : "Unknown error",
    });
    // Surface the error so the controller can tell the client to retry
    throw new HttpError("Failed to send password reset email. Please try again later.", 503);
  }
}

/**
 * Complete a password reset using the token from the email link.
 */
export async function resetPassword(token: string, newPassword: string): Promise<void> {
  const tokenHash = crypto.createHash("sha256").update(token.trim()).digest("hex");
  const now = new Date();

  const [resetRecord] = await db
    .select()
    .from(passwordResetTokens)
    .where(
      and(
        eq(passwordResetTokens.tokenHash, tokenHash),
        isNull(passwordResetTokens.consumedAt),
        gt(passwordResetTokens.expiresAt, now),
      ),
    )
    .limit(1);

  if (!resetRecord) {
    throw new HttpError("Invalid or expired password reset link.", 400);
  }

  const newHash = await bcrypt.hash(newPassword, 10);

  await db
    .update(users)
    .set({ passwordHash: newHash, updatedAt: now })
    .where(eq(users.id, resetRecord.userId));

  await db
    .update(passwordResetTokens)
    .set({ consumedAt: now })
    .where(eq(passwordResetTokens.id, resetRecord.id));

  // Best-effort sync to Neon Auth
  if (isNeonAuthAvailable()) {
    const [userRow] = await db
      .select({ email: users.email })
      .from(users)
      .where(eq(users.id, resetRecord.userId))
      .limit(1);

    if (userRow) {
      try {
        await syncPasswordToNeonAuth({
          userId: resetRecord.userId,
          email: userRow.email,
          passwordHash: newHash,
        });
      } catch (error) {
        console.warn(`${RESET_TOKEN_LOG_NS} reset:neon-sync-failed`, {
          userId: resetRecord.userId,
          message: error instanceof Error ? error.message : "Unknown error",
        });
      }
    }
  }

  console.info(`${RESET_TOKEN_LOG_NS} reset:success`, { userId: resetRecord.userId });
}

