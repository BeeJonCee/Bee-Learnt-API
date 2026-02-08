import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";
import * as nodemailer from "nodemailer";
import { eq, sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { db as authDb } from "../core/database/neon-auth-db.js";
import { neonAuthUsers } from "../core/database/neon-auth-schema.js";
import { roles, users } from "../core/database/schema/index.js";
import { env } from "../config/env.js";
import { HttpError } from "../shared/utils/http-error.js";
import type { BeeLearntRole } from "../shared/types/auth.js";
import {
  isNeonAuthAvailable,
  getNeonAuthUserByEmail,
  syncNeonAuthUserToApp,
  authenticateViaNeonAuth
} from "./neon-auth-sync.js";

type RegisterInput = {
  name: string;
  email: string;
  password: string;
  role: BeeLearntRole;
};

type LoginInput = {
  email: string;
  password: string;
};

function generateSixDigitCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendVerificationEmail(toEmail: string, code: string) {
  // Use process.env directly so this continues to work even if env.ts hasn't been expanded yet.
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASSWORD;
  const from = process.env.FROM_EMAIL ?? "noreply@beelearnt.com";
  const appName = process.env.APP_NAME ?? "BeeLearnt";

  // No SMTP configured: log code for local dev and exit gracefully.
  if (!host || !user || !pass) {
    console.log(`[auth] Verification code for ${toEmail}: ${code}`);
    return;
  }

  const port = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587;
  const secure = process.env.SMTP_SECURE === "true" || port === 465;

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  });

  await transporter.sendMail({
    from,
    to: toEmail,
    subject: `${appName} email verification code`,
    text: `Your ${appName} verification code is: ${code}\n\nThis code expires in 10 minutes.`,
  });
}

export async function sendEmailVerificationCode(email: string) {
  const code = generateSixDigitCode();
  const codeHash = await bcrypt.hash(code, 10);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  await db.execute(sql`
    INSERT INTO email_verification_codes (email, code_hash, expires_at)
    VALUES (${email}, ${codeHash}, ${expiresAt})
  `);

  await sendVerificationEmail(email, code);
}

export async function confirmEmailVerificationCode(email: string, code: string) {
  const result = await db.execute<{
    id: number;
    code_hash: string;
    expires_at: Date;
    consumed_at: Date | null;
  }>(sql`
    SELECT id, code_hash, expires_at, consumed_at
    FROM email_verification_codes
    WHERE email = ${email}
    ORDER BY created_at DESC
    LIMIT 1
  `);

  const row = result.rows[0];
  if (!row || row.consumed_at) {
    throw new HttpError("Invalid verification code.", 400);
  }

  const expiresAt = row.expires_at instanceof Date ? row.expires_at : new Date(row.expires_at);
  if (expiresAt.getTime() < Date.now()) {
    throw new HttpError("Verification code expired.", 400);
  }

  const valid = await bcrypt.compare(code, row.code_hash);
  if (!valid) {
    throw new HttpError("Invalid verification code.", 400);
  }

  await db.execute(sql`
    UPDATE email_verification_codes
    SET consumed_at = NOW()
    WHERE id = ${row.id}
  `);

  // Update emailVerified in neondb.user (if available)
  if (authDb) {
    try {
      await authDb
        .update(neonAuthUsers)
        .set({ emailVerified: true, updatedAt: new Date() })
        .where(eq(neonAuthUsers.email, email));
    } catch (error: any) {
      if (error?.code !== "42P01" && error?.code !== "3F000") {
        console.warn("Could not update emailVerified in neondb:", error);
      }
    }
  }
}

export async function registerUser(input: RegisterInput) {
  // Normalize role to uppercase
  const normalizedRole = input.role.toUpperCase() as BeeLearntRole;

  // Check for existing user in beelearnt database
  const existing = await db.select().from(users).where(eq(users.email, input.email));
  if (existing.length > 0) {
    throw new HttpError("Email already in use.", 409);
  }

  // Check Neon Auth if available
  if (isNeonAuthAvailable()) {
    try {
      const neonUser = await getNeonAuthUserByEmail(input.email);
      if (neonUser) {
        throw new HttpError("Email already in use.", 409);
      }
    } catch (error: any) {
      if (error instanceof HttpError) throw error;
      // If Neon Auth check fails, continue (not critical)
      console.warn("Could not check Neon Auth:", error.message);
    }
  }

  // Get role
  const [roleRow] = await db.select().from(roles).where(eq(roles.name, normalizedRole));
  if (!roleRow) {
    throw new HttpError("Role not found.", 400);
  }

  const passwordHash = await bcrypt.hash(input.password, 10);
  const userId = randomUUID();

  // Create user in beelearnt database only (local auth)
  const [created] = await db
    .insert(users)
    .values({
      id: userId,
      name: input.name,
      email: input.email,
      passwordHash, // Store for local auth
      roleId: roleRow.id,
    })
    .returning();

  console.log(`✓ User registered in beelearnt: ${input.email} (${normalizedRole})`);

  return { 
    id: created.id, 
    email: created.email, 
    name: created.name, 
    role: normalizedRole 
  };
}

export async function loginUser(input: LoginInput) {
  if (!env.jwtSecret) {
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

  // Path 1: Local auth — user exists with a passwordHash in beelearnt
  if (user?.passwordHash) {
    const valid = await bcrypt.compare(input.password, user.passwordHash);
    if (!valid) {
      throw new HttpError("Invalid email or password.", 401);
    }

    const normalizedRole = user.role.toUpperCase() as BeeLearntRole;

    const token = jwt.sign(
      { id: user.id, role: normalizedRole, email: user.email, name: user.name },
      env.jwtSecret,
      { expiresIn: "7d" }
    );

    await db.update(users).set({ lastLoginAt: new Date() }).where(eq(users.id, user.id));
    console.log(`✓ User logged in (local): ${user.email} (Role: ${normalizedRole})`);

    return {
      token,
      user: { id: user.id, name: user.name, email: user.email, role: normalizedRole },
    };
  }

  // Path 2: Neon Auth fallback — check neondb credential account
  if (isNeonAuthAvailable()) {
    const neonResult = await authenticateViaNeonAuth(input.email, input.password);
    if (neonResult) {
      const token = jwt.sign(
        { id: neonResult.id, role: neonResult.role, email: neonResult.email, name: neonResult.name },
        env.jwtSecret,
        { expiresIn: "7d" }
      );

      await db.update(users).set({ lastLoginAt: new Date() }).where(eq(users.id, neonResult.id));
      console.log(`✓ User logged in (Neon Auth): ${neonResult.email} (Role: ${neonResult.role})`);

      return {
        token,
        user: { id: neonResult.id, name: neonResult.name, email: neonResult.email, role: neonResult.role },
      };
    }
  }

  throw new HttpError("Invalid email or password.", 401);
}
