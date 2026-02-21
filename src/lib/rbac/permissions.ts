/**
 * RBAC Permission System for BeeLearnt
 * 
 * This file defines all permissions and role mappings for the platform.
 * Permissions are granular capabilities that determine what actions users can perform.
 */

import type { BeeLearntRole } from "../../shared/types/auth.js";

// ============ PERMISSION DEFINITIONS ============

export type Permission =
  // Authentication & User Management
  | "auth:register"
  | "auth:login"
  | "user:read:own"
  | "user:read:all"
  | "user:write:own"
  | "user:write:all"
  | "user:delete"
  | "user:role:assign"

  // Student Profile Management
  | "student:profile:create"
  | "student:profile:read:own"
  | "student:profile:read:linked"
  | "student:profile:read:all"
  | "student:profile:write:own"
  | "student:profile:write:linked"
  | "student:profile:write:all"

  // Parent Profile Management
  | "parent:profile:create"
  | "parent:profile:read:own"
  | "parent:profile:read:all"
  | "parent:profile:write:own"
  | "parent:profile:write:all"
  | "parent:children:link"
  | "parent:children:view"
  | "parent:children:unlink"

  // Content (Subjects, Modules, Lessons)
  | "content:read:public"
  | "content:read:assigned"
  | "content:read:all"
  | "content:write"
  | "content:delete"

  // Module Assignment
  | "module:assign"
  | "module:unassign"
  | "module:read:own"
  | "module:read:linked"
  | "module:read:all"

  // Module Unlock & Token System
  | "token:generate"
  | "token:request"
  | "token:use"
  | "token:view"

  // Quiz Management
  | "quiz:read:assigned"
  | "quiz:read:all"
  | "quiz:take"
  | "quiz:write"
  | "quiz:delete"
  | "quiz:grade"

  // Quiz Results & Answers
  | "quiz:results:read:own"
  | "quiz:results:read:linked"
  | "quiz:results:read:all"
  | "quiz:answers:view:own"
  | "quiz:answers:view:correct"
  | "quiz:answers:view:linked"
  | "quiz:answers:view:all"

  // Progress Tracking
  | "progress:read:own"
  | "progress:read:linked"
  | "progress:read:all"
  | "progress:write:own"
  | "progress:write:all"

  // Assignments
  | "assignment:read:own"
  | "assignment:read:linked"
  | "assignment:read:all"
  | "assignment:create"
  | "assignment:update"
  | "assignment:delete"

  // Tutoring (for Tutor role)
  | "tutor:session:create"
  | "tutor:session:manage"
  | "tutor:students:view"
  | "tutor:feedback:give"
  | "tutor:feedback:receive"

  // Admin & Audit
  | "admin:analytics"
  | "admin:audit:view"
  | "admin:audit:export"
  | "admin:system:config"
  | "admin:users:manage"
  | "admin:roles:manage";

// ============ ROLE TO PERMISSIONS MAPPING ============

export const ROLE_PERMISSIONS: Record<BeeLearntRole, Permission[]> = {
  STUDENT: [
    // Authentication
    "auth:register",
    "auth:login",
    "user:read:own",
    "user:write:own",

    // Student Profile
    "student:profile:read:own",
    "student:profile:write:own",

    // Content Access (only assigned modules)
    "content:read:assigned",

    // Module Access
    "module:read:own",
    "token:use",

    // Quizzes
    "quiz:read:assigned",
    "quiz:take",
    "quiz:results:read:own",
    "quiz:answers:view:own",
    "quiz:answers:view:correct",

    // Progress
    "progress:read:own",
    "progress:write:own",

    // Assignments
    "assignment:read:own",
  ],

  PARENT: [
    // Authentication
    "auth:register",
    "auth:login",
    "user:read:own",
    "user:write:own",

    // Parent Profile
    "parent:profile:create",
    "parent:profile:read:own",
    "parent:profile:write:own",

    // Children Management
    "parent:children:link",
    "parent:children:view",
    "parent:children:unlink",
    "student:profile:create",
    "student:profile:read:linked",
    "student:profile:write:linked",

    // Content Access (can view what children are learning)
    "content:read:assigned",

    // Module Access (for children)
    "module:read:linked",

    // Quizzes (view children's results)
    "quiz:read:assigned",
    "quiz:results:read:linked",
    "quiz:answers:view:linked",

    // Progress (view children's progress)
    "progress:read:linked",

    // Assignments (view children's assignments)
    "assignment:read:linked",
  ],

  TUTOR: [
    // Authentication
    "auth:register",
    "auth:login",
    "user:read:own",
    "user:read:all",
    "user:write:own",

    // Content Access
    "content:read:all",
    "content:write",

    // Module Assignment & Unlock
    "module:assign",
    "module:unassign",
    "module:read:all",
    "token:generate",
    "token:request",
    "token:view",

    // Quizzes
    "quiz:read:all",
    "quiz:take",
    "quiz:write",
    "quiz:delete",
    "quiz:grade",
    "quiz:results:read:all",
    "quiz:answers:view:all",

    // Progress
    "progress:read:all",
    "progress:write:all",

    // Assignments
    "assignment:read:all",
    "assignment:create",
    "assignment:update",
    "assignment:delete",

    // Student Management
    "student:profile:read:all",

    // Tutoring
    "tutor:session:create",
    "tutor:session:manage",
    "tutor:students:view",
    "tutor:feedback:give",
    "tutor:feedback:receive",
  ],

  ADMIN: [
    // Full access to everything
    "auth:register",
    "auth:login",
    "user:read:own",
    "user:read:all",
    "user:write:own",
    "user:write:all",
    "user:delete",
    "user:role:assign",

    // Profiles
    "student:profile:create",
    "student:profile:read:all",
    "student:profile:write:all",
    "parent:profile:create",
    "parent:profile:read:all",
    "parent:profile:write:all",
    "parent:children:link",
    "parent:children:view",
    "parent:children:unlink",

    // Content
    "content:read:all",
    "content:write",
    "content:delete",

    // Modules
    "module:assign",
    "module:unassign",
    "module:read:all",
    "token:generate",
    "token:request",
    "token:use",
    "token:view",

    // Quizzes
    "quiz:read:all",
    "quiz:take",
    "quiz:write",
    "quiz:delete",
    "quiz:grade",
    "quiz:results:read:all",
    "quiz:answers:view:own",
    "quiz:answers:view:correct",
    "quiz:answers:view:all",

    // Progress
    "progress:read:all",
    "progress:write:all",

    // Assignments
    "assignment:read:all",
    "assignment:create",
    "assignment:update",
    "assignment:delete",

    // Tutoring
    "tutor:session:create",
    "tutor:session:manage",
    "tutor:students:view",
    "tutor:feedback:give",
    "tutor:feedback:receive",

    // Admin
    "admin:analytics",
    "admin:audit:view",
    "admin:audit:export",
    "admin:system:config",
    "admin:users:manage",
    "admin:roles:manage",
  ],
};

/**
 * Check if a role has a specific permission
 */
export function hasPermission(role: BeeLearntRole, permission: Permission): boolean {
  const permissions = ROLE_PERMISSIONS[role];
  return permissions.includes(permission);
}

/**
 * Check if a role has ANY of the specified permissions
 */
export function hasAnyPermission(role: BeeLearntRole, permissions: Permission[]): boolean {
  return permissions.some((perm) => hasPermission(role, perm));
}

/**
 * Check if a role has ALL of the specified permissions
 */
export function hasAllPermissions(role: BeeLearntRole, permissions: Permission[]): boolean {
  return permissions.every((perm) => hasPermission(role, perm));
}

/**
 * Get all permissions for a role
 */
export function getRolePermissions(role: BeeLearntRole): Permission[] {
  return ROLE_PERMISSIONS[role];
}
