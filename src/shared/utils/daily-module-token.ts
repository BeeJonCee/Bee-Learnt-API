/**
 * Daily Module Token System
 * 
 * Manages daily-rotating tokens for module unlocking:
 * - Tokens change every day
 * - Tokens are hashed (never stored in plain text)
 * - Rate limited (max attempts per student per day)
 * - Email integration for token distribution
 */

import { eq, and, gte, lte } from "drizzle-orm";
import * as bcrypt from "bcryptjs";
import * as crypto from "crypto";
import { db } from "../../core/database/index.js";
import { dailyModuleTokens, tokenAttempts, moduleAssignments, modules } from "../../core/database/schema/index.js";

// ============ CONFIGURATION ============

const TOKEN_LENGTH = 8; // 8 alphanumeric characters
const MAX_ATTEMPTS_PER_DAY = 5;
const LOCKOUT_DURATION_MINUTES = 30;
const TOKEN_EXPIRY_HOURS = 24; // Token valid for current day

// ============ TOKEN GENERATION ============

/**
 * Generate a random alphanumeric token
 */
export function generateToken(length: number = TOKEN_LENGTH): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Removed similar-looking chars
  let token = "";
  for (let i = 0; i < length; i++) {
    token += chars[crypto.randomInt(0, chars.length)];
  }
  return token;
}

/**
 * Hash a token using bcrypt
 */
export async function hashToken(token: string): Promise<string> {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(token, salt);
}

/**
 * Verify a token against its hash
 */
export async function verifyToken(token: string, hash: string): Promise<boolean> {
  return bcrypt.compare(token, hash);
}

/**
 * Get start and end of current day
 */
function getDayBoundaries(): { start: Date; end: Date } {
  const start = new Date();
  start.setHours(0, 0, 0, 0);

  const end = new Date(start);
  end.setHours(23, 59, 59, 999);

  return { start, end };
}

// ============ TOKEN CREATION ============

/**
 * Create or get existing token for a module on current day
 * 
 * @param moduleId Module ID
 * @param createdBy User ID of admin/tutor creating the token
 * @returns Plain text token (only returned once, never stored)
 */
export async function createDailyToken(
  moduleId: number,
  createdBy: string
): Promise<{ token: string; tokenId: number; expiresAt: Date }> {
  const { start, end } = getDayBoundaries();

  // Check if token already exists for today
  const existingToken = await db.query.dailyModuleTokens.findFirst({
    where: and(
      eq(dailyModuleTokens.moduleId, moduleId),
      gte(dailyModuleTokens.date, start),
      lte(dailyModuleTokens.date, end)
    ),
  });

  if (existingToken) {
    // Token already exists for today, return new token but same record
    // This ensures we always give a fresh token even if one was generated
    const newToken = generateToken();
    const newTokenHash = await hashToken(newToken);

    // Update the existing token with new hash
    await db
      .update(dailyModuleTokens)
      .set({
        tokenHash: newTokenHash,
        expiresAt: end,
      })
      .where(eq(dailyModuleTokens.id, existingToken.id));

    return {
      token: newToken,
      tokenId: existingToken.id,
      expiresAt: end,
    };
  }

  // Create new token
  const token = generateToken();
  const tokenHash = await hashToken(token);

  const [newToken] = await db
    .insert(dailyModuleTokens)
    .values({
      moduleId,
      date: start,
      tokenHash,
      expiresAt: end,
      createdBy,
    })
    .returning();

  return {
    token,
    tokenId: newToken.id,
    expiresAt: end,
  };
}

// ============ TOKEN VALIDATION ============

/**
 * Check if student has exceeded attempt limit
 */
async function checkRateLimit(studentId: string, moduleId: number): Promise<{
  allowed: boolean;
  attemptsUsed: number;
  lockedUntil: Date | null;
}> {
  const { start, end } = getDayBoundaries();

  // Get today's attempts
  const attempts = await db.query.tokenAttempts.findMany({
    where: and(
      eq(tokenAttempts.studentId, studentId),
      eq(tokenAttempts.moduleId, moduleId),
      gte(tokenAttempts.date, start),
      lte(tokenAttempts.date, end)
    ),
    orderBy: (attempts, { desc }) => [desc(attempts.createdAt)],
  });

  const totalAttempts = attempts.reduce((sum, attempt) => sum + attempt.attemptsCount, 0);

  // Check if locked out
  const latestAttempt = attempts[0];
  if (latestAttempt?.lockedUntil && new Date() < latestAttempt.lockedUntil) {
    return {
      allowed: false,
      attemptsUsed: totalAttempts,
      lockedUntil: latestAttempt.lockedUntil,
    };
  }

  // Check if exceeded max attempts
  if (totalAttempts >= MAX_ATTEMPTS_PER_DAY) {
    // Lock the student out
    const lockoutUntil = new Date();
    lockoutUntil.setMinutes(lockoutUntil.getMinutes() + LOCKOUT_DURATION_MINUTES);

    return {
      allowed: false,
      attemptsUsed: totalAttempts,
      lockedUntil: lockoutUntil,
    };
  }

  return {
    allowed: true,
    attemptsUsed: totalAttempts,
    lockedUntil: null,
  };
}

/**
 * Record a token attempt
 */
async function recordAttempt(
  studentId: string,
  moduleId: number,
  tokenId: number | null,
  attemptedToken: string,
  success: boolean,
  lockedUntil: Date | null
): Promise<void> {
  const { start } = getDayBoundaries();

  await db.insert(tokenAttempts).values({
    studentId,
    moduleId,
    tokenId,
    date: start,
    attemptToken: attemptedToken,
    success,
    attemptsCount: 1,
    lockedUntil,
    createdAt: new Date(),
  });
}

/**
 * Validate a token and unlock module if valid
 * 
 * @param studentId Student attempting to unlock
 * @param moduleId Module to unlock
 * @param token Token provided by student
 * @returns Validation result
 */
export async function validateAndUnlockModule(
  studentId: string,
  moduleId: number,
  token: string
): Promise<{
  success: boolean;
  message: string;
  attemptsRemaining?: number;
  lockedUntil?: Date;
}> {
  // 1. Check rate limit
  const rateLimit = await checkRateLimit(studentId, moduleId);

  if (!rateLimit.allowed) {
    return {
      success: false,
      message: rateLimit.lockedUntil
        ? `Too many failed attempts. Try again after ${rateLimit.lockedUntil.toLocaleTimeString()}`
        : "Maximum attempts exceeded for today",
      attemptsRemaining: 0,
      lockedUntil: rateLimit.lockedUntil || undefined,
    };
  }

  // 2. Get today's token for this module
  const { start, end } = getDayBoundaries();
  const dailyToken = await db.query.dailyModuleTokens.findFirst({
    where: and(
      eq(dailyModuleTokens.moduleId, moduleId),
      gte(dailyModuleTokens.date, start),
      lte(dailyModuleTokens.date, end)
    ),
  });

  if (!dailyToken) {
    await recordAttempt(studentId, moduleId, null, token, false, null);
    return {
      success: false,
      message: "No token has been generated for this module today",
      attemptsRemaining: MAX_ATTEMPTS_PER_DAY - (rateLimit.attemptsUsed + 1),
    };
  }

  // 3. Verify token
  const isValid = await verifyToken(token, dailyToken.tokenHash);

  if (!isValid) {
    const newAttempts = rateLimit.attemptsUsed + 1;
    const lockedUntil = newAttempts >= MAX_ATTEMPTS_PER_DAY 
      ? new Date(Date.now() + LOCKOUT_DURATION_MINUTES * 60 * 1000)
      : null;

    await recordAttempt(studentId, moduleId, dailyToken.id, token, false, lockedUntil);

    return {
      success: false,
      message: "Invalid token",
      attemptsRemaining: Math.max(0, MAX_ATTEMPTS_PER_DAY - newAttempts),
      lockedUntil: lockedUntil || undefined,
    };
  }

  // 4. Token is valid - unlock the module
  await recordAttempt(studentId, moduleId, dailyToken.id, token, true, null);

  // Update module assignment to unlocked
  const assignment = await db.query.moduleAssignments.findFirst({
    where: and(
      eq(moduleAssignments.studentId, studentId),
      eq(moduleAssignments.moduleId, moduleId)
    ),
  });

  if (assignment) {
    await db
      .update(moduleAssignments)
      .set({
        unlockedAt: new Date(),
        status: "in_progress",
      })
      .where(eq(moduleAssignments.id, assignment.id));
  }

  return {
    success: true,
    message: "Module unlocked successfully!",
    attemptsRemaining: MAX_ATTEMPTS_PER_DAY - (rateLimit.attemptsUsed + 1),
  };
}

// ============ TOKEN INFORMATION ============

/**
 * Get token info for a module (admin/tutor view)
 */
export async function getTokenInfo(moduleId: number): Promise<{
  exists: boolean;
  expiresAt?: Date;
  createdBy?: string;
  emailedAt?: Date | null;
} | null> {
  const { start, end } = getDayBoundaries();

  const token = await db.query.dailyModuleTokens.findFirst({
    where: and(
      eq(dailyModuleTokens.moduleId, moduleId),
      gte(dailyModuleTokens.date, start),
      lte(dailyModuleTokens.date, end)
    ),
  });

  if (!token) {
    return { exists: false };
  }

  return {
    exists: true,
    expiresAt: token.expiresAt,
    createdBy: token.createdBy,
    emailedAt: token.emailedAt,
  };
}

/**
 * Mark token as emailed
 */
export async function markTokenAsEmailed(tokenId: number): Promise<void> {
  await db
    .update(dailyModuleTokens)
    .set({ emailedAt: new Date() })
    .where(eq(dailyModuleTokens.id, tokenId));
}

/**
 * Get attempt statistics for a student
 */
export async function getAttemptStats(studentId: string, moduleId: number): Promise<{
  attemptsToday: number;
  lastAttempt: Date | null;
  isLocked: boolean;
  lockedUntil: Date | null;
}> {
  const { start, end } = getDayBoundaries();

  const attempts = await db.query.tokenAttempts.findMany({
    where: and(
      eq(tokenAttempts.studentId, studentId),
      eq(tokenAttempts.moduleId, moduleId),
      gte(tokenAttempts.date, start),
      lte(tokenAttempts.date, end)
    ),
    orderBy: (attempts, { desc }) => [desc(attempts.createdAt)],
  });

  const totalAttempts = attempts.reduce((sum, attempt) => sum + attempt.attemptsCount, 0);
  const latestAttempt = attempts[0];
  const isLocked = latestAttempt?.lockedUntil ? new Date() < latestAttempt.lockedUntil : false;

  return {
    attemptsToday: totalAttempts,
    lastAttempt: latestAttempt?.createdAt || null,
    isLocked,
    lockedUntil: isLocked && latestAttempt?.lockedUntil ? latestAttempt.lockedUntil : null,
  };
}
