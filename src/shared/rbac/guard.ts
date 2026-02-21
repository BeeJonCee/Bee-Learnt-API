import type { NextFunction, Request, Response } from "express";
import { and, eq } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import { parentStudentLinks, moduleAssignments, studentProfiles } from "../../core/database/schema/index.js";
import type { BeeLearntRole } from "../../shared/types/auth.js";
import { hasAnyPermission, type Permission } from "./permissions.js";

type OwnershipType = "student" | "module_assignment";

type OwnershipConfig = {
  type: OwnershipType;
  idParam: string;
  allowSelf?: boolean;
  allowParent?: boolean;
  allowTutor?: boolean;
};

type GuardConfig = {
  roles?: BeeLearntRole[];
  permissions?: Permission[];
  ownership?: OwnershipConfig;
};

async function checkStudentOwnership(
  userId: string,
  role: BeeLearntRole,
  studentId: string,
  config: OwnershipConfig
): Promise<boolean> {
  if (role === "ADMIN") return true;
  if (role === "TUTOR" && config.allowTutor) return true;
  if (role === "STUDENT" && config.allowSelf && userId === studentId) return true;
  if (role === "PARENT" && config.allowParent) {
    const link = await db
      .select({ parentId: parentStudentLinks.parentId })
      .from(parentStudentLinks)
      .where(
        and(
          eq(parentStudentLinks.parentId, userId),
          eq(parentStudentLinks.studentId, studentId)
        )
      )
      .limit(1);
    return link.length > 0;
  }
  return false;
}

async function checkOwnership(req: Request, config: OwnershipConfig): Promise<boolean> {
  const user = req.user!;

  if (config.type === "student") {
    const studentId = req.params[config.idParam] as string;
    if (!studentId) return false;
    return checkStudentOwnership(user.id, user.role, studentId, config);
  }

  if (config.type === "module_assignment") {
    if (user.role === "ADMIN") return true;
    if (user.role === "TUTOR" && config.allowTutor) return true;

    const assignmentId = Number(req.params[config.idParam]);
    if (Number.isNaN(assignmentId)) return false;

    const [assignment] = await db
      .select({ studentId: moduleAssignments.studentId })
      .from(moduleAssignments)
      .where(eq(moduleAssignments.id, assignmentId));

    if (!assignment) return false;
    return checkStudentOwnership(user.id, user.role, assignment.studentId, config);
  }

  return false;
}

export function guard(config: GuardConfig) {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ message: "Unauthorized - authentication required" });
      return;
    }

    const { roles, permissions, ownership } = config;

    // Role check — user's role must be in the allowed list
    if (roles && roles.length > 0 && !roles.includes(req.user.role)) {
      res.status(403).json({
        message: "Forbidden - insufficient role",
        required: roles,
        role: req.user.role,
      });
      return;
    }

    // Permission check — user must have at least one listed permission
    if (permissions && permissions.length > 0 && !hasAnyPermission(req.user.role, permissions)) {
      res.status(403).json({
        message: "Forbidden - insufficient permissions",
        required: permissions,
        role: req.user.role,
      });
      return;
    }

    // Ownership check — verify the user has access to this specific resource
    if (ownership) {
      try {
        const allowed = await checkOwnership(req, ownership);
        if (!allowed) {
          res.status(403).json({ message: "Forbidden - access denied to this resource" });
          return;
        }
      } catch {
        res.status(500).json({ message: "Internal server error during access check" });
        return;
      }
    }

    next();
  };
}

/**
 * Returns the student IDs the given user is permitted to access.
 * - ADMIN / TUTOR: all student IDs in the system
 * - PARENT: only their linked children
 * - STUDENT: only their own ID
 */
export async function getAccessibleStudentIds(
  userId: string,
  role: BeeLearntRole
): Promise<string[]> {
  if (role === "ADMIN" || role === "TUTOR") {
    // Every user with a student profile is a student
    const rows = await db.select({ userId: studentProfiles.userId }).from(studentProfiles);
    return rows.map((r) => r.userId);
  }

  if (role === "PARENT") {
    const links = await db
      .select({ studentId: parentStudentLinks.studentId })
      .from(parentStudentLinks)
      .where(eq(parentStudentLinks.parentId, userId));
    return links.map((r) => r.studentId);
  }

  // STUDENT — only themselves
  return [userId];
}

export function requireOwnership(config: OwnershipConfig) {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ message: "Unauthorized - authentication required" });
      return;
    }

    try {
      const allowed = await checkOwnership(req, config);
      if (!allowed) {
        res.status(403).json({ message: "Forbidden - access denied to this resource" });
        return;
      }
    } catch {
      res.status(500).json({ message: "Internal server error during access check" });
      return;
    }

    next();
  };
}
