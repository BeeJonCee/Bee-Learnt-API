/**
 * RBAC Guard System
 * 
 * Provides middleware and utility functions for enforcing role-based access control
 * and ownership checks throughout the application.
 */

import type { NextFunction, Request, Response } from "express";
import { eq, and } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import { parentStudentLinks, moduleAssignments, roles, users } from "../../core/database/schema/index.js";
import type { BeeLearntRole } from "../../shared/types/auth.js";
import { hasPermission, hasAnyPermission, hasAllPermissions, type Permission } from "./permissions.js";

// ============ TYPE DEFINITIONS ============

export interface GuardOptions {
  requireAuth?: boolean;
  roles?: BeeLearntRole[];
  permissions?: Permission[];
  requireAll?: boolean; // If true, requires all permissions; if false, requires any
  ownership?: OwnershipCheck;
}

export interface OwnershipCheck {
  type: "student" | "parent" | "module_assignment" | "user";
  idParam?: string; // URL parameter name (default: "id" or "studentId")
  allowSelf?: boolean; // Allow if user ID matches
  allowParent?: boolean; // Allow if user is parent of student
  allowTutor?: boolean; // Allow if user is assigned tutor
}

// ============ CORE GUARD MIDDLEWARE ============

/**
 * Main guard middleware that enforces authentication, roles, permissions, and ownership
 */
export function guard(options: GuardOptions = {}) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // 1. Check authentication
      if (options.requireAuth !== false) {
        if (!req.user) {
          res.status(401).json({ error: "Authentication required" });
          return;
        }
      }

      // If no user, skip further checks
      if (!req.user) {
        next();
        return;
      }

      // 2. Check roles
      if (options.roles && options.roles.length > 0) {
        if (!options.roles.includes(req.user.role)) {
          res.status(403).json({
            error: "Insufficient permissions",
            required: options.roles,
            current: req.user.role,
          });
          return;
        }
      }

      // 3. Check permissions
      if (options.permissions && options.permissions.length > 0) {
        const hasPerms = options.requireAll
          ? hasAllPermissions(req.user.role, options.permissions)
          : hasAnyPermission(req.user.role, options.permissions);

        if (!hasPerms) {
          res.status(403).json({
            error: "Insufficient permissions",
            required: options.permissions,
            current: req.user.role,
          });
          return;
        }
      }

      // 4. Check ownership
      if (options.ownership) {
        const hasOwnership = await checkOwnership(req, options.ownership);
        if (!hasOwnership) {
          res.status(403).json({
            error: "Access denied",
            message: "You do not have permission to access this resource",
          });
          return;
        }
      }

      next();
    } catch (error) {
      console.error("[guard] Error:", error);
      res.status(500).json({ error: "Authorization check failed" });
    }
  };
}

// ============ OWNERSHIP CHECKS ============

/**
 * Check if the user has ownership/access rights to the resource
 */
async function checkOwnership(req: Request, check: OwnershipCheck): Promise<boolean> {
  if (!req.user) return false;

  const userId = req.user.id;
  const role = req.user.role;
  const idParam = check.idParam || "id";
  const resourceId = req.params[idParam] || req.body[idParam];

  if (!resourceId) {
    console.warn(`[checkOwnership] Missing resource ID in params or body: ${idParam}`);
    return false;
  }

  // Admin always has access
  if (role === "ADMIN") return true;

  switch (check.type) {
    case "user":
      return checkUserOwnership(userId, resourceId, check);

    case "student":
      return checkStudentOwnership(userId, role, resourceId, check);

    case "parent":
      return checkParentOwnership(userId, resourceId);

    case "module_assignment":
      return checkModuleAssignmentOwnership(userId, role, resourceId, check);

    default:
      console.warn(`[checkOwnership] Unknown ownership type: ${check.type}`);
      return false;
  }
}

/**
 * Check if user owns their own resource
 */
function checkUserOwnership(userId: string, resourceId: string, check: OwnershipCheck): boolean {
  if (check.allowSelf && userId === resourceId) {
    return true;
  }
  return false;
}

/**
 * Check if user has access to student resource
 * - Student can access their own data
 * - Parent can access linked children
 * - Tutor can access assigned students
 */
async function checkStudentOwnership(
  userId: string,
  role: BeeLearntRole,
  studentId: string,
  check: OwnershipCheck
): Promise<boolean> {
  // Student accessing their own data
  if (check.allowSelf && role === "STUDENT" && userId === studentId) {
    return true;
  }

  // Parent accessing linked child
  if (check.allowParent && role === "PARENT") {
    const link = await db.query.parentStudentLinks.findFirst({
      where: and(
        eq(parentStudentLinks.parentId, userId),
        eq(parentStudentLinks.studentId, studentId)
      ),
    });
    if (link) return true;
  }

  // Tutor accessing assigned student (via module assignments or tutoring sessions)
  if (check.allowTutor && role === "TUTOR") {
    const assignment = await db.query.moduleAssignments.findFirst({
      where: and(
        eq(moduleAssignments.studentId, studentId),
        eq(moduleAssignments.assignedBy, userId)
      ),
    });
    if (assignment) return true;
  }

  return false;
}

/**
 * Check if user is the parent
 */
async function checkParentOwnership(userId: string, parentId: string): Promise<boolean> {
  return userId === parentId;
}

/**
 * Check if user has access to module assignment
 */
async function checkModuleAssignmentOwnership(
  userId: string,
  role: BeeLearntRole,
  assignmentId: string,
  check: OwnershipCheck
): Promise<boolean> {
  const assignment = await db.query.moduleAssignments.findFirst({
    where: eq(moduleAssignments.id, parseInt(assignmentId, 10)),
  });

  if (!assignment) return false;

  // Student accessing their own assignment
  if (check.allowSelf && role === "STUDENT" && assignment.studentId === userId) {
    return true;
  }

  // Parent accessing child's assignment
  if (check.allowParent && role === "PARENT") {
    const link = await db.query.parentStudentLinks.findFirst({
      where: and(
        eq(parentStudentLinks.parentId, userId),
        eq(parentStudentLinks.studentId, assignment.studentId)
      ),
    });
    if (link) return true;
  }

  // Tutor who assigned it
  if (check.allowTutor && role === "TUTOR" && assignment.assignedBy === userId) {
    return true;
  }

  return false;
}

// ============ CONVENIENCE MIDDLEWARE ============

/**
 * Require authentication only
 */
export function requireAuth() {
  return guard({ requireAuth: true });
}

/**
 * Require specific role(s)
 */
export function requireRole(...roles: BeeLearntRole[]) {
  return guard({ requireAuth: true, roles });
}

/**
 * Require specific permission(s)
 */
export function requirePermission(...permissions: Permission[]) {
  return guard({ requireAuth: true, permissions, requireAll: false });
}

/**
 * Require all specified permissions
 */
export function requireAllPermissions(...permissions: Permission[]) {
  return guard({ requireAuth: true, permissions, requireAll: true });
}

/**
 * Require ownership of the resource
 */
export function requireOwnership(ownership: OwnershipCheck) {
  return guard({ requireAuth: true, ownership });
}

/**
 * Combined: require role AND ownership
 */
export function requireRoleAndOwnership(roles: BeeLearntRole[], ownership: OwnershipCheck) {
  return guard({ requireAuth: true, roles, ownership });
}

// ============ UTILITY FUNCTIONS ============

/**
 * Check if current user can access student data
 */
export async function canAccessStudent(
  userId: string,
  role: BeeLearntRole,
  studentId: string
): Promise<boolean> {
  // Admin can access all
  if (role === "ADMIN") return true;

  // Student can access own data
  if (role === "STUDENT" && userId === studentId) return true;

  // Parent can access linked children
  if (role === "PARENT") {
    const link = await db.query.parentStudentLinks.findFirst({
      where: and(
        eq(parentStudentLinks.parentId, userId),
        eq(parentStudentLinks.studentId, studentId)
      ),
    });
    return !!link;
  }

  // Tutor can access assigned students
  if (role === "TUTOR") {
    const assignment = await db.query.moduleAssignments.findFirst({
      where: and(
        eq(moduleAssignments.studentId, studentId),
        eq(moduleAssignments.assignedBy, userId)
      ),
    });
    return !!assignment;
  }

  return false;
}

/**
 * Get list of student IDs the user can access
 */
export async function getAccessibleStudentIds(
  userId: string,
  role: BeeLearntRole
): Promise<string[]> {
  // Admin/tutor can access all students.
  // Do not assume role IDs are stable across databases.
  if (role === "ADMIN" || role === "TUTOR") {
    const allStudents = await db
      .select({ id: users.id })
      .from(users)
      .innerJoin(roles, eq(users.roleId, roles.id))
      .where(eq(roles.name, "STUDENT"));

    return allStudents.map((student) => student.id);
  }

  // Parent can access linked children
  if (role === "PARENT") {
    const links = await db.query.parentStudentLinks.findMany({
      where: eq(parentStudentLinks.parentId, userId),
    });
    return links.map((link) => link.studentId);
  }

  // Student can only access themselves
  if (role === "STUDENT") {
    return [userId];
  }

  return [];
}
