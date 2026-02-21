/**
 * Audit Logging Service
 * 
 * Tracks sensitive operations and user activities for security and compliance:
 * - Token generation and usage
 * - Module assignments
 * - Role changes
 * - Quiz submissions
 * - Student-parent linking
 * - Admin actions
 */

import { db } from "../../core/database/index.js";
import { auditLogs } from "../../core/database/schema/index.js";
import type { Request } from "express";

// ============ AUDIT ACTION TYPES ============

export type AuditAction =
  // Authentication
  | "auth.register"
  | "auth.login"
  | "auth.logout"
  | "auth.password_reset"

  // User Management
  | "user.create"
  | "user.update"
  | "user.delete"
  | "user.role_change"

  // Student-Parent Linking
  | "student.link"
  | "student.unlink"
  | "student.profile_create"
  | "student.profile_update"

  // Module Operations
  | "module.assign"
  | "module.unassign"
  | "module.unlock_request"
  | "module.unlock_success"
  | "module.unlock_failure"

  // Token Operations
  | "token.generate"
  | "token.email_sent"
  | "token.attempt"
  | "token.rate_limit_exceeded"

  // Quiz Operations
  | "quiz.create"
  | "quiz.update"
  | "quiz.delete"
  | "quiz.attempt_start"
  | "quiz.attempt_submit"
  | "quiz.grade"
  | "quiz.visibility_update"

  // Content Operations
  | "content.create"
  | "content.update"
  | "content.delete"
  | "content.publish"

  // Progress Operations
  | "progress.update"
  | "progress.view"

  // Assignment Operations
  | "assignment.create"
  | "assignment.update"
  | "assignment.delete"
  | "assignment.submit"

  // Admin Operations
  | "admin.settings_change"
  | "admin.bulk_operation"
  | "admin.export_data"
  | "admin.import_data"

  // Security Events
  | "security.suspicious_activity"
  | "security.rate_limit_hit"
  | "security.unauthorized_access"
  | "security.password_failure";

export type AuditEntity =
  | "user"
  | "student"
  | "parent"
  | "module"
  | "lesson"
  | "quiz"
  | "assignment"
  | "token"
  | "progress"
  | "system";

// ============ AUDIT LOGGING FUNCTIONS ============

interface AuditLogInput {
  actorId?: string | null; // User performing the action
  action: AuditAction;
  entity: AuditEntity;
  entityId?: number | null;
  details?: Record<string, unknown>;
  ipAddress?: string | null;
  req?: Request; // Optionally extract IP from request
}

/**
 * Create an audit log entry
 */
export async function logAudit(input: AuditLogInput): Promise<void> {
  try {
    // Extract IP address from request if provided
    let ipAddress = input.ipAddress;
    if (!ipAddress && input.req) {
      ipAddress = extractIpAddress(input.req);
    }

    await db.insert(auditLogs).values({
      actorId: input.actorId || null,
      action: input.action,
      entity: input.entity,
      entityId: input.entityId || null,
      details: input.details || {},
      ipAddress: ipAddress || null,
      createdAt: new Date(),
    });

    console.log(`[Audit] ${input.action} on ${input.entity}${input.entityId ? ` #${input.entityId}` : ""} by ${input.actorId || "system"}`);
  } catch (error) {
    // Don't throw - audit logging should not break the main flow
    console.error("[Audit] Failed to log:", error);
  }
}

/**
 * Extract IP address from Express request
 */
function extractIpAddress(req: Request): string {
  return (
    (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
    (req.headers["x-real-ip"] as string) ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

// ============ CONVENIENCE LOGGING FUNCTIONS ============

/**
 * Log authentication event
 */
export async function logAuth(action: Extract<AuditAction, `auth.${string}`>, userId: string | null, req?: Request, details?: Record<string, unknown>) {
  await logAudit({
    actorId: userId,
    action,
    entity: "user",
    entityId: null,
    details,
    req,
  });
}

/**
 * Log token operation
 */
export async function logToken(
  action: Extract<AuditAction, `token.${string}`>,
  actorId: string,
  moduleId: number,
  details?: Record<string, unknown>,
  req?: Request
) {
  await logAudit({
    actorId,
    action,
    entity: "token",
    entityId: moduleId,
    details,
    req,
  });
}

/**
 * Log module operation
 */
export async function logModule(
  action: Extract<AuditAction, `module.${string}`>,
  actorId: string | null,
  moduleId: number,
  details?: Record<string, unknown>,
  req?: Request
) {
  await logAudit({
    actorId,
    action,
    entity: "module",
    entityId: moduleId,
    details,
    req,
  });
}

/**
 * Log quiz operation
 */
export async function logQuiz(
  action: Extract<AuditAction, `quiz.${string}`>,
  actorId: string,
  quizId: number,
  details?: Record<string, unknown>,
  req?: Request
) {
  await logAudit({
    actorId,
    action,
    entity: "quiz",
    entityId: quizId,
    details,
    req,
  });
}

/**
 * Log student-parent linking
 */
export async function logStudentLink(
  action: Extract<AuditAction, `student.${string}`>,
  actorId: string,
  studentId: string,
  details?: Record<string, unknown>,
  req?: Request
) {
  await logAudit({
    actorId,
    action,
    entity: "student",
    entityId: null,
    details: { ...details, studentId },
    req,
  });
}

/**
 * Log admin action
 */
export async function logAdmin(
  action: Extract<AuditAction, `admin.${string}`>,
  actorId: string,
  details?: Record<string, unknown>,
  req?: Request
) {
  await logAudit({
    actorId,
    action,
    entity: "system",
    entityId: null,
    details,
    req,
  });
}

/**
 * Log security event
 */
export async function logSecurity(
  action: Extract<AuditAction, `security.${string}`>,
  actorId: string | null,
  details?: Record<string, unknown>,
  req?: Request
) {
  await logAudit({
    actorId,
    action,
    entity: "system",
    entityId: null,
    details,
    req,
  });
}

// ============ AUDIT QUERIES ============

/**
 * Get audit logs for a specific user
 */
export async function getUserAuditLogs(userId: string, limit: number = 50) {
  return db.query.auditLogs.findMany({
    where: (logs, { eq }) => eq(logs.actorId, userId),
    orderBy: (logs, { desc }) => [desc(logs.createdAt)],
    limit,
  });
}

/**
 * Get audit logs for a specific entity
 */
export async function getEntityAuditLogs(entity: AuditEntity, entityId: number, limit: number = 50) {
  return db.query.auditLogs.findMany({
    where: (logs, { eq, and }) => and(eq(logs.entity, entity), eq(logs.entityId, entityId)),
    orderBy: (logs, { desc }) => [desc(logs.createdAt)],
    limit,
  });
}

/**
 * Get recent audit logs (admin view)
 */
export async function getRecentAuditLogs(limit: number = 100) {
  return db.query.auditLogs.findMany({
    orderBy: (logs, { desc }) => [desc(logs.createdAt)],
    limit,
  });
}

/**
 * Get security-related audit logs
 */
export async function getSecurityLogs(limit: number = 100) {
  return db.query.auditLogs.findMany({
    where: (logs, { like }) => like(logs.action, "security.%"),
    orderBy: (logs, { desc }) => [desc(logs.createdAt)],
    limit,
  });
}

/**
 * Get token-related audit logs for a module
 */
export async function getTokenLogs(moduleId: number, limit: number = 50) {
  return db.query.auditLogs.findMany({
    where: (logs, { eq, and, like }) =>
      and(eq(logs.entity, "token"), eq(logs.entityId, moduleId)),
    orderBy: (logs, { desc }) => [desc(logs.createdAt)],
    limit,
  });
}
