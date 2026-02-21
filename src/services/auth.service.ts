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
import jwt from "jsonwebtoken";
import { eq } from "drizzle-orm";
import { randomUUID } from "crypto";
import { db } from "../core/database/index.js";
import { roles, users } from "../core/database/schema/index.js";
import { env } from "../config/env.js";
import { HttpError } from "../shared/utils/http-error.js";
import type { BeeLearntRole } from "../shared/types/auth.js";
import {
  isNeonAuthAvailable,
  authenticateViaNeonAuth,
} from "./neon-auth-sync.js";
import {
  syncPasswordToNeonAuth,
  syncToNeonAuthUser,
} from "../shared/utils/schema-sync.js";

type LoginInput = {
  email: string;
  password: string;
};

type RegisterInput = {
  name: string;
  email: string;
  password: string;
  role: BeeLearntRole;
};

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

export async function registerUser(input: RegisterInput) {
  const normalizedEmail = input.email.trim().toLowerCase();
  const normalizedRole = normalizeRole(input.role);
  const maskedEmail = maskEmail(normalizedEmail);

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
      passwordHash,
      roleId: roleRow.id,
    })
    .returning({
      id: users.id,
      name: users.name,
      email: users.email,
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
    role: normalizedRole,
  };
}

export async function loginUser(input: LoginInput) {
  const maskedEmail = maskEmail(input.email);
  console.info(`${AUTH_SERVICE_LOG_NS} login:start`, { email: maskedEmail });

  if (!env.jwtSecret) {
    console.error(`${AUTH_SERVICE_LOG_NS} login:missing-jwt-secret`, {
      email: maskedEmail,
    });
    throw new HttpError("JWT secret is not configured.", 500);
  }

  // Look up user in beelearnt database
  const [user] = await db
    .select({
      id: users.id,
      name: users.name,
      email: users.email,
      passwordHash: users.passwordHash,
      role: roles.name,
    })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id))
    .where(eq(users.email, input.email));

  // Path 1: Local auth - user exists with a passwordHash in beelearnt
  if (user?.passwordHash) {
    const valid = await bcrypt.compare(input.password, user.passwordHash);
    if (!valid) {
      console.warn(`${AUTH_SERVICE_LOG_NS} login:local-password-mismatch`, {
        email: maskedEmail,
        userId: user.id,
      });
      throw new HttpError("Invalid email or password.", 401);
    }

    const normalizedRole = user.role.toUpperCase() as BeeLearntRole;

    const token = jwt.sign(
      { id: user.id, role: normalizedRole, email: user.email, name: user.name },
      env.jwtSecret,
      { expiresIn: "7d" },
    );

    await db
      .update(users)
      .set({ lastLoginAt: new Date() })
      .where(eq(users.id, user.id));

    console.info(`${AUTH_SERVICE_LOG_NS} login:local-success`, {
      email: maskedEmail,
      userId: user.id,
      role: normalizedRole,
    });

    return {
      token,
      user: { id: user.id, name: user.name, email: user.email, role: normalizedRole },
    };
  }

  // Path 2: Neon Auth fallback - check neondb.neon_auth.account for credential provider
  if (isNeonAuthAvailable()) {
    console.info(`${AUTH_SERVICE_LOG_NS} login:neon-fallback:start`, {
      email: maskedEmail,
    });

    const neonResult = await authenticateViaNeonAuth(input.email, input.password);
    if (neonResult) {
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
        token,
        user: {
          id: neonResult.id,
          name: neonResult.name,
          email: neonResult.email,
          role: neonResult.role,
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
