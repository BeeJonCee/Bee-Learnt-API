/**
 * Compatibility RBAC adapter.
 *
 * Canonical RBAC role-permission mapping lives in shared/rbac/permissions.ts.
 * This module preserves the historical core/guards/rbac API and permission
 * names used across routes while delegating permission evaluation to shared.
 */

import type { NextFunction, Request, Response } from "express";
import {
  hasPermission as sharedHasPermission,
  type Permission as SharedPermission,
} from "../../shared/rbac/permissions.js";
import type { BeeLearntRole } from "../../shared/types/auth.js";

// Legacy permission names used by existing routes/controllers.
export type Permission =
  | "content:read"
  | "content:write"
  | "content:delete"
  | "quiz:read"
  | "quiz:take"
  | "quiz:write"
  | "quiz:grade"
  | "module:assign"
  | "module:unlock"
  | "progress:read:own"
  | "progress:read:students"
  | "progress:read:children"
  | "progress:write"
  | "user:read"
  | "user:write"
  | "user:delete"
  | "user:role:assign"
  | "tutor:session:create"
  | "tutor:session:manage"
  | "tutor:students:view"
  | "parent:children:view"
  | "parent:children:link"
  | "admin:analytics"
  | "admin:audit"
  | "admin:system";

const LEGACY_TO_SHARED: Record<Permission, SharedPermission[]> = {
  "content:read": ["content:read:public", "content:read:assigned", "content:read:all"],
  "content:write": ["content:write"],
  "content:delete": ["content:delete"],
  "quiz:read": ["quiz:read:assigned", "quiz:read:all"],
  "quiz:take": ["quiz:take"],
  "quiz:write": ["quiz:write"],
  "quiz:grade": ["quiz:grade"],
  "module:assign": ["module:assign"],
  // Historical module unlock capability maps to token-based unlock permissions.
  "module:unlock": ["token:generate", "token:request", "token:use", "token:view"],
  "progress:read:own": ["progress:read:own"],
  "progress:read:students": ["progress:read:all"],
  "progress:read:children": ["progress:read:linked"],
  "progress:write": ["progress:write:own", "progress:write:all"],
  "user:read": ["user:read:own", "user:read:all"],
  "user:write": ["user:write:own", "user:write:all"],
  "user:delete": ["user:delete"],
  "user:role:assign": ["user:role:assign"],
  "tutor:session:create": ["tutor:session:create"],
  "tutor:session:manage": ["tutor:session:manage"],
  "tutor:students:view": ["tutor:students:view"],
  "parent:children:view": ["parent:children:view"],
  "parent:children:link": ["parent:children:link"],
  "admin:analytics": ["admin:analytics"],
  "admin:audit": ["admin:audit:view", "admin:audit:export"],
  "admin:system": ["admin:system:config"],
};

const LEGACY_PERMISSIONS = Object.keys(LEGACY_TO_SHARED) as Permission[];

function hasMappedPermission(role: BeeLearntRole, permission: Permission): boolean {
  const mapped = LEGACY_TO_SHARED[permission];
  return mapped.some((sharedPermission) =>
    sharedHasPermission(role, sharedPermission),
  );
}

export function hasPermission(role: BeeLearntRole, permission: Permission): boolean {
  return hasMappedPermission(role, permission);
}

export function hasAnyPermission(
  role: BeeLearntRole,
  permissions: Permission[],
): boolean {
  return permissions.some((permission) => hasPermission(role, permission));
}

export function hasAllPermissions(
  role: BeeLearntRole,
  permissions: Permission[],
): boolean {
  return permissions.every((permission) => hasPermission(role, permission));
}

/** Require ANY of the listed permissions. */
export function requirePermission(...permissions: Permission[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ message: "Unauthorized - authentication required" });
      return;
    }
    if (!hasAnyPermission(req.user.role, permissions)) {
      res.status(403).json({
        message: "Forbidden - insufficient permissions",
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
      res.status(401).json({ message: "Unauthorized - authentication required" });
      return;
    }
    if (!hasAllPermissions(req.user.role, permissions)) {
      res.status(403).json({
        message: "Forbidden - insufficient permissions",
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
        message: `Forbidden - only ${allowed.join(", ")} can access this resource`,
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
      res.status(403).json({ message: "Forbidden - can only access your own data" });
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
      res.status(403).json({ message: "Forbidden - students cannot edit this resource" });
      return;
    }
    next();
  };
}

export const onlyAdmin = onlyRoles("ADMIN");
export const onlyTutor = onlyRoles("TUTOR");
export const onlyStudent = onlyRoles("STUDENT");
export const onlyParent = onlyRoles("PARENT");
export const onlyAdminOrTutor = onlyRoles("ADMIN", "TUTOR");
export const onlyStaff = onlyRoles("ADMIN", "TUTOR");
export const notStudent = onlyRoles("ADMIN", "TUTOR", "PARENT");

export function getPermissionsForRole(role: BeeLearntRole): Permission[] {
  return LEGACY_PERMISSIONS.filter((permission) => hasPermission(role, permission));
}

export function isStaff(role: BeeLearntRole): boolean {
  return role === "ADMIN" || role === "TUTOR";
}

