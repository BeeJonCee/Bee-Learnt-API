/**
 * Role-Based Access Control (RBAC) for BeeLearnt
 *
 * Permissions per role:
 * - STUDENT: View content, take quizzes, track own progress
 * - TUTOR: Assign modules, manage tutoring sessions, view student progress
 * - ADMIN: Full access — manage all content, users, assignments, system settings
 * - PARENT: View linked students' progress (read-only)
 */

import type { NextFunction, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../database/index.js";
import type { BeeLearntRole } from "../../shared/types/auth.js";

// ─── Permission Definitions ────────────────────────────────────────

export type Permission =
  // Content
  | "content:read"
  | "content:write"
  | "content:delete"
  // Quiz
  | "quiz:read"
  | "quiz:take"
  | "quiz:write"
  | "quiz:grade"
  // Modules
  | "module:assign"
  | "module:unlock"
  // Progress
  | "progress:read:own"
  | "progress:read:students"
  | "progress:read:children"
  | "progress:write"
  // Users
  | "user:read"
  | "user:write"
  | "user:delete"
  | "user:role:assign"
  // Tutor
  | "tutor:session:create"
  | "tutor:session:manage"
  | "tutor:students:view"
  // Parent
  | "parent:children:view"
  | "parent:children:link"
  // Admin
  | "admin:analytics"
  | "admin:audit"
  | "admin:system";

const ROLE_PERMISSIONS: Record<BeeLearntRole, Permission[]> = {
  STUDENT: [
    "content:read",
    "quiz:read",
    "quiz:take",
    "progress:read:own",
    "progress:write",
    "user:read",
  ],
  TUTOR: [
    "content:read",
    "quiz:read",
    "quiz:take",
    "quiz:write",
    "quiz:grade",
    "module:assign",
    "module:unlock",
    "progress:read:own",
    "progress:read:students",
    "progress:write",
    "user:read",
    "tutor:session:create",
    "tutor:session:manage",
    "tutor:students:view",
  ],
  PARENT: [
    "content:read",
    "quiz:read",
    "progress:read:own",
    "progress:read:children",
    "user:read",
    "parent:children:view",
    "parent:children:link",
  ],
  ADMIN: [
    "content:read",
    "content:write",
    "content:delete",
    "quiz:read",
    "quiz:take",
    "quiz:write",
    "quiz:grade",
    "module:assign",
    "module:unlock",
    "progress:read:own",
    "progress:read:students",
    "progress:read:children",
    "progress:write",
    "user:read",
    "user:write",
    "user:delete",
    "user:role:assign",
    "tutor:session:create",
    "tutor:session:manage",
    "tutor:students:view",
    "parent:children:view",
    "parent:children:link",
    "admin:analytics",
    "admin:audit",
    "admin:system",
  ],
};

// ─── Permission Helpers ────────────────────────────────────────────

export function hasPermission(role: BeeLearntRole, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false;
}

export function hasAnyPermission(role: BeeLearntRole, permissions: Permission[]): boolean {
  return permissions.some((p) => hasPermission(role, p));
}

export function hasAllPermissions(role: BeeLearntRole, permissions: Permission[]): boolean {
  return permissions.every((p) => hasPermission(role, p));
}

// ─── Middleware Factories ──────────────────────────────────────────

/** Require ANY of the listed permissions. */
export function requirePermission(...permissions: Permission[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ message: "Unauthorized — authentication required" });
      return;
    }
    if (!hasAnyPermission(req.user.role, permissions)) {
      res.status(403).json({
        message: "Forbidden — insufficient permissions",
        required: permissions,
        role: req.user.role,
      });
      return;
    }
    next();
  };
}

/** Require ALL of the listed permissions. */
export function requireAllPermissions_mw(...permissions: Permission[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ message: "Unauthorized — authentication required" });
      return;
    }
    if (!hasAllPermissions(req.user.role, permissions)) {
      res.status(403).json({
        message: "Forbidden — insufficient permissions",
        required: permissions,
        role: req.user.role,
      });
      return;
    }
    next();
  };
}

/** Only allow specific roles. */
export function onlyRoles(...allowed: BeeLearntRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }
    if (!allowed.includes(req.user.role)) {
      res.status(403).json({
        message: `Forbidden — only ${allowed.join(", ")} can access this resource`,
      });
      return;
    }
    next();
  };
}

/** Only allow the data owner (or ADMIN). */
export function requireOwnData(userIdParam = "userId") {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }
    if (req.user.role === "ADMIN") {
      next();
      return;
    }
    const targetUserId = req.params[userIdParam] || req.body?.[userIdParam];
    if (targetUserId && targetUserId !== req.user.id) {
      res.status(403).json({ message: "Forbidden — can only access your own data" });
      return;
    }
    next();
  };
}

/** Prevent students from writing. */
export function preventStudentEdit() {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }
    if (req.user.role === "STUDENT") {
      res.status(403).json({ message: "Forbidden — students cannot edit this resource" });
      return;
    }
    next();
  };
}

// ─── Shorthand Exports ─────────────────────────────────────────────

export const onlyAdmin = onlyRoles("ADMIN");
export const onlyTutor = onlyRoles("TUTOR");
export const onlyStudent = onlyRoles("STUDENT");
export const onlyParent = onlyRoles("PARENT");
export const onlyAdminOrTutor = onlyRoles("ADMIN", "TUTOR");
export const onlyStaff = onlyRoles("ADMIN", "TUTOR");
export const notStudent = onlyRoles("ADMIN", "TUTOR", "PARENT");

// ─── Utility Functions ─────────────────────────────────────────────

export function getPermissionsForRole(role: BeeLearntRole): Permission[] {
  return ROLE_PERMISSIONS[role] ?? [];
}

export function isStaff(role: BeeLearntRole): boolean {
  return role === "ADMIN" || role === "TUTOR";
}
