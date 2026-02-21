/**
 * Module Unlock Controller
 * 
 * Handles module unlocking via daily tokens:
 * - Generate unlock token (Admin/Tutor)
 * - Request token email (Admin/Tutor)
 * - Submit token for unlock (Student)
 * - View token attempts (Student/Admin)
 */

import type { Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { db } from "../core/database/index.js";
import { moduleAssignments, modules, users } from "../core/database/schema/index.js";
import {
  createDailyToken,
  validateAndUnlockModule,
  getTokenInfo,
  markTokenAsEmailed,
  getAttemptStats,
} from "../lib/tokens/dailyModuleToken.js";
import { sendTokenEmail } from "../lib/email/sendToken.js";
import { logToken, logModule, logSecurity } from "../lib/audit/auditLog.js";
import { env } from "../config/env.js";

// ============ GENERATE TOKEN (Admin/Tutor) ============

/**
 * POST /api/modules/:moduleId/token/generate
 * Generate a daily unlock token for a module
 * Role: ADMIN, TUTOR
 */
export const generateModuleToken = asyncHandler(async (req: Request, res: Response) => {
  const moduleId = req.params.moduleId as string;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  // Check if module exists
  const module = await db.query.modules.findFirst({
    where: eq(modules.id, parseInt(moduleId, 10)),
  });

  if (!module) {
    res.status(404).json({ error: "Module not found" });
    return;
  }

  // Generate token
  const { token, tokenId, expiresAt } = await createDailyToken(
    parseInt(moduleId, 10),
    req.user.id
  );

  // Log token generation
  await logToken(
    "token.generate",
    req.user.id,
    parseInt(moduleId, 10),
    { tokenId, expiresAt },
    req
  );

  res.json({
    message: "Token generated successfully",
    token, // Return token only once
    tokenId,
    expiresAt,
    moduleName: module.title,
  });
});

// ============ REQUEST TOKEN EMAIL (Admin/Tutor) ============

/**
 * POST /api/modules/:moduleId/token/request
 * Generate token and email it to admin
 * Role: ADMIN, TUTOR
 */
export const requestModuleToken = asyncHandler(async (req: Request, res: Response) => {
  const moduleId = req.params.moduleId as string;
  const { studentId } = req.body; // Optional: specify which student

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  // Check if module exists
  const module = await db.query.modules.findFirst({
    where: eq(modules.id, parseInt(moduleId, 10)),
  });

  if (!module) {
    res.status(404).json({ error: "Module not found" });
    return;
  }

  // Get student info if provided
  let studentName: string | undefined;
  if (studentId) {
    const student = await db.query.users.findFirst({
      where: eq(users.id, studentId),
    });
    studentName = student?.name;
  }

  // Generate token
  const { token, tokenId, expiresAt } = await createDailyToken(
    parseInt(moduleId, 10),
    req.user.id
  );

  // Send email to admin
  const emailResult = await sendTokenEmail({
    moduleName: module.title,
    moduleId: parseInt(moduleId, 10),
    token,
    studentName,
    requestedBy: req.user.name ?? "Unknown",
    expiresAt,
    adminEmail: env.adminEmail,
  });

  if (!emailResult.success) {
    res.status(500).json({
      error: "Failed to send email",
      message: emailResult.error,
    });
    return;
  }

  // Mark token as emailed
  await markTokenAsEmailed(tokenId);

  // Log token request
  await logToken(
    "token.email_sent",
    req.user.id,
    parseInt(moduleId, 10),
    { tokenId, studentId, emailMessageId: emailResult.messageId },
    req
  );

  res.json({
    message: "Token generated and emailed to admin successfully",
    tokenId,
    expiresAt,
    emailSent: true,
  });
});

// ============ UNLOCK MODULE WITH TOKEN (Student) ============

/**
 * POST /api/modules/:moduleId/unlock
 * Student submits token to unlock module
 * Role: STUDENT
 */
export const unlockModule = asyncHandler(async (req: Request, res: Response) => {
  const moduleId = req.params.moduleId as string;
  const { token } = req.body;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  if (!token || typeof token !== "string" || token.trim().length === 0) {
    res.status(400).json({ error: "Token is required" });
    return;
  }

  const studentId = req.user.id;

  // Check if module exists
  const module = await db.query.modules.findFirst({
    where: eq(modules.id, parseInt(moduleId, 10)),
  });

  if (!module) {
    res.status(404).json({ error: "Module not found" });
    return;
  }

  // Check if student has this module assigned
  const assignment = await db.query.moduleAssignments.findFirst({
    where: and(
      eq(moduleAssignments.studentId, studentId),
      eq(moduleAssignments.moduleId, parseInt(moduleId, 10))
    ),
  });

  if (!assignment) {
    res.status(403).json({
      error: "Module not assigned to you",
      message: "This module must be assigned to you before you can unlock it",
    });
    return;
  }

  // Check if already unlocked
  if (assignment.unlockedAt) {
    res.status(400).json({
      error: "Module already unlocked",
      message: "You have already unlocked this module",
      unlockedAt: assignment.unlockedAt,
    });
    return;
  }

  // Validate token and unlock
  const result = await validateAndUnlockModule(
    studentId,
    parseInt(moduleId, 10),
    token.trim().toUpperCase()
  );

  // Log attempt
  await logToken(
    "token.attempt",
    studentId,
    parseInt(moduleId, 10),
    {
      success: result.success,
      attemptsRemaining: result.attemptsRemaining,
      lockedUntil: result.lockedUntil,
    },
    req
  );

  if (result.success) {
    // Log module unlock
    await logModule(
      "module.unlock_success",
      studentId,
      parseInt(moduleId, 10),
      { assignmentId: assignment.id },
      req
    );

    res.json({
      success: true,
      message: result.message,
      module: {
        id: module.id,
        title: module.title,
        description: module.description,
      },
    });
  } else {
    // Log rate limit if exceeded
    if (result.attemptsRemaining === 0) {
      await logSecurity(
        "security.rate_limit_hit",
        studentId,
        { moduleId: parseInt(moduleId, 10), lockedUntil: result.lockedUntil },
        req
      );
    }

    res.status(400).json({
      success: false,
      error: result.message,
      attemptsRemaining: result.attemptsRemaining,
      lockedUntil: result.lockedUntil,
    });
  }
});

// ============ GET TOKEN STATUS (Student) ============

/**
 * GET /api/modules/:moduleId/token/status
 * Get token unlock status for a module
 * Role: STUDENT (own), ADMIN, TUTOR
 */
export const getTokenStatus = asyncHandler(async (req: Request, res: Response) => {
  const moduleId = req.params.moduleId as string;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const studentId = req.user.id;

  // Check if module exists
  const module = await db.query.modules.findFirst({
    where: eq(modules.id, parseInt(moduleId, 10)),
  });

  if (!module) {
    res.status(404).json({ error: "Module not found" });
    return;
  }

  // Get assignment status
  const assignment = await db.query.moduleAssignments.findFirst({
    where: and(
      eq(moduleAssignments.studentId, studentId),
      eq(moduleAssignments.moduleId, parseInt(moduleId, 10))
    ),
  });

  if (!assignment) {
    res.status(403).json({
      error: "Module not assigned to you",
    });
    return;
  }

  // Get attempt stats
  const attemptStats = await getAttemptStats(studentId, parseInt(moduleId, 10));

  // Get token info (for admin/tutor)
  let tokenInfo = null;
  if (req.user.role === "ADMIN" || req.user.role === "TUTOR") {
    tokenInfo = await getTokenInfo(parseInt(moduleId, 10));
  }

  res.json({
    moduleId: parseInt(moduleId, 10),
    moduleName: module.title,
    isAssigned: true,
    isUnlocked: !!assignment.unlockedAt,
    unlockedAt: assignment.unlockedAt,
    attemptStats,
    tokenInfo,
  });
});

// ============ GET TOKEN INFO (Admin/Tutor) ============

/**
 * GET /api/modules/:moduleId/token/info
 * Get detailed token information
 * Role: ADMIN, TUTOR
 */
export const getModuleTokenInfo = asyncHandler(async (req: Request, res: Response) => {
  const moduleId = req.params.moduleId as string;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  // Check if module exists
  const module = await db.query.modules.findFirst({
    where: eq(modules.id, parseInt(moduleId, 10)),
  });

  if (!module) {
    res.status(404).json({ error: "Module not found" });
    return;
  }

  const tokenInfo = await getTokenInfo(parseInt(moduleId, 10));

  res.json({
    moduleId: parseInt(moduleId, 10),
    moduleName: module.title,
    tokenInfo,
  });
});
