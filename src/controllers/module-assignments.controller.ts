/**
 * Module Assignment Controller
 * 
 * Handles module assignment operations:
 * - Assign modules to students (Admin/Tutor)
 * - View assigned modules (Student/Parent)
 * - Unassign modules (Admin/Tutor)
 * - Get assignment details
 */

import type { Request, Response } from "express";
import { eq, and, inArray } from "drizzle-orm";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { db } from "../core/database/index.js";
import { moduleAssignments, modules, users } from "../core/database/schema/index.js";
import { logModule, logAudit, logAdmin } from "../lib/audit/auditLog.js";
import { getAccessibleStudentIds } from "../lib/rbac/guard.js";

// ============ ASSIGN MODULE TO STUDENT ============

/**
 * POST /api/module-assignments
 * Assign a module to a student
 * Role: ADMIN, TUTOR
 */
export const assignModuleToStudent = asyncHandler(async (req: Request, res: Response) => {
  const { studentId, moduleId, dueDate, notes } = req.body;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  // Validate input
  if (!studentId || !moduleId) {
    res.status(400).json({ error: "studentId and moduleId are required" });
    return;
  }

  // Check if student exists
  const student = await db.query.users.findFirst({
    where: eq(users.id, studentId),
  });

  if (!student) {
    res.status(404).json({ error: "Student not found" });
    return;
  }

  // Check if module exists
  const module = await db.query.modules.findFirst({
    where: eq(modules.id, moduleId),
  });

  if (!module) {
    res.status(404).json({ error: "Module not found" });
    return;
  }

  // Check if already assigned
  const existing = await db.query.moduleAssignments.findFirst({
    where: and(
      eq(moduleAssignments.studentId, studentId),
      eq(moduleAssignments.moduleId, moduleId)
    ),
  });

  if (existing) {
    res.status(409).json({ error: "Module already assigned to this student" });
    return;
  }

  // Create assignment
  const [assignment] = await db
    .insert(moduleAssignments)
    .values({
      studentId,
      moduleId,
      assignedBy: req.user.id,
      status: "assigned",
      dueDate: dueDate ? new Date(dueDate) : null,
      notes: notes || null,
      assignedAt: new Date(),
    })
    .returning();

  // Log audit
  await logModule(
    "module.assign",
    req.user.id,
    moduleId,
    { studentId, assignmentId: assignment.id, dueDate, notes },
    req
  );

  res.status(201).json({
    message: "Module assigned successfully",
    assignment,
  });
});

// ============ GET STUDENT'S ASSIGNED MODULES ============

/**
 * GET /api/students/:studentId/modules
 * Get all modules assigned to a student
 * Role: STUDENT (own), PARENT (linked), TUTOR, ADMIN
 */
export const getStudentModules = asyncHandler(async (req: Request, res: Response) => {
  const studentId = req.params.studentId as string;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  // Permission check is handled by guard middleware, but verify access
  const accessibleIds = await getAccessibleStudentIds(req.user.id, req.user.role);

  if (!accessibleIds.includes(studentId)) {
    res.status(403).json({ error: "Access denied" });
    return;
  }

  // Get assignments with module details
  const assignments = await db.query.moduleAssignments.findMany({
    where: eq(moduleAssignments.studentId, studentId),
    with: {
      module: {
        with: {
          subject: true,
        },
      },
    },
    orderBy: (assignments, { desc }) => [desc(assignments.assignedAt)],
  });

  // Map to include more details
  const enrichedAssignments = assignments.map((assignment) => ({
    id: assignment.id,
    moduleId: assignment.moduleId,
    moduleName: assignment.module.title,
    moduleDescription: assignment.module.description,
    subjectName: assignment.module.subject.name,
    grade: assignment.module.grade,
    status: assignment.status,
    assignedAt: assignment.assignedAt,
    dueDate: assignment.dueDate,
    unlockedAt: assignment.unlockedAt,
    completedAt: assignment.completedAt,
    notes: assignment.notes,
    isLocked: !assignment.unlockedAt,
  }));

  res.json({
    studentId,
    assignments: enrichedAssignments,
    total: enrichedAssignments.length,
  });
});

// ============ GET ALL MODULE ASSIGNMENTS (ADMIN/TUTOR) ============

/**
 * GET /api/module-assignments
 * Get all module assignments with optional filters
 * Role: ADMIN, TUTOR
 */
export const getAllModuleAssignments = asyncHandler(async (req: Request, res: Response) => {
  const { studentId, moduleId, status, assignedBy } = req.query;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  // Build where clause
  const conditions = [];

  if (studentId) {
    conditions.push(eq(moduleAssignments.studentId, studentId as string));
  }

  if (moduleId) {
    conditions.push(eq(moduleAssignments.moduleId, parseInt(moduleId as string, 10)));
  }

  if (status) {
    conditions.push(eq(moduleAssignments.status, status as any));
  }

  if (assignedBy) {
    conditions.push(eq(moduleAssignments.assignedBy, assignedBy as string));
  }

  const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

  const assignments = await db.query.moduleAssignments.findMany({
    where: whereClause,
    with: {
      module: true,
      student: true,
      assigner: true,
    },
    orderBy: (assignments, { desc }) => [desc(assignments.assignedAt)],
  });

  res.json({
    assignments,
    total: assignments.length,
  });
});

// ============ GET SINGLE ASSIGNMENT DETAILS ============

/**
 * GET /api/module-assignments/:id
 * Get details of a specific assignment
 * Role: Based on ownership (student/parent/tutor/admin)
 */
export const getAssignmentDetails = asyncHandler(async (req: Request, res: Response) => {
  const id = req.params.id as string;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const assignment = await db.query.moduleAssignments.findFirst({
    where: eq(moduleAssignments.id, parseInt(id, 10)),
    with: {
      module: {
        with: {
          subject: true,
        },
      },
      student: true,
      assigner: true,
    },
  });

  if (!assignment) {
    res.status(404).json({ error: "Assignment not found" });
    return;
  }

  // Check access
  const accessibleIds = await getAccessibleStudentIds(req.user.id, req.user.role);

  if (!accessibleIds.includes(assignment.studentId) && req.user.role !== "ADMIN") {
    res.status(403).json({ error: "Access denied" });
    return;
  }

  res.json({ assignment });
});

// ============ UPDATE ASSIGNMENT ============

/**
 * PATCH /api/module-assignments/:id
 * Update an assignment (status, due date, notes)
 * Role: ADMIN, TUTOR (who assigned it)
 */
export const updateAssignment = asyncHandler(async (req: Request, res: Response) => {
  const id = req.params.id as string;
  const { status, dueDate, notes } = req.body;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const assignment = await db.query.moduleAssignments.findFirst({
    where: eq(moduleAssignments.id, parseInt(id, 10)),
  });

  if (!assignment) {
    res.status(404).json({ error: "Assignment not found" });
    return;
  }

  // Only admin or the assigner can update
  if (req.user.role !== "ADMIN" && assignment.assignedBy !== req.user.id) {
    res.status(403).json({ error: "Only the assigner or admin can update this assignment" });
    return;
  }

  // Build update object
  const updateData: any = {};

  if (status !== undefined) updateData.status = status;
  if (dueDate !== undefined) updateData.dueDate = dueDate ? new Date(dueDate) : null;
  if (notes !== undefined) updateData.notes = notes;

  if (Object.keys(updateData).length === 0) {
    res.status(400).json({ error: "No fields to update" });
    return;
  }

  const [updated] = await db
    .update(moduleAssignments)
    .set(updateData)
    .where(eq(moduleAssignments.id, parseInt(id, 10)))
    .returning();

  await logAudit({
    actorId: req.user.id,
    action: "assignment.update",
    entity: "module",
    entityId: assignment.moduleId,
    details: { assignmentId: id, updates: updateData },
    req,
  });

  res.json({
    message: "Assignment updated successfully",
    assignment: updated,
  });
});

// ============ DELETE ASSIGNMENT ============

/**
 * DELETE /api/module-assignments/:id
 * Remove a module assignment
 * Role: ADMIN, TUTOR (who assigned it)
 */
export const deleteAssignment = asyncHandler(async (req: Request, res: Response) => {
  const id = req.params.id as string;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const assignment = await db.query.moduleAssignments.findFirst({
    where: eq(moduleAssignments.id, parseInt(id, 10)),
  });

  if (!assignment) {
    res.status(404).json({ error: "Assignment not found" });
    return;
  }

  // Only admin or the assigner can delete
  if (req.user.role !== "ADMIN" && assignment.assignedBy !== req.user.id) {
    res.status(403).json({ error: "Only the assigner or admin can delete this assignment" });
    return;
  }

  await db.delete(moduleAssignments).where(eq(moduleAssignments.id, parseInt(id, 10)));

  await logModule(
    "module.unassign",
    req.user.id,
    assignment.moduleId,
    { studentId: assignment.studentId, assignmentId: id },
    req
  );

  res.json({ message: "Assignment deleted successfully" });
});

// ============ BULK ASSIGN MODULES ============

/**
 * POST /api/module-assignments/bulk
 * Assign multiple modules to multiple students
 * Role: ADMIN, TUTOR
 */
export const bulkAssignModules = asyncHandler(async (req: Request, res: Response) => {
  const { studentIds, moduleIds, dueDate, notes } = req.body;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  if (!Array.isArray(studentIds) || !Array.isArray(moduleIds)) {
    res.status(400).json({ error: "studentIds and moduleIds must be arrays" });
    return;
  }

  if (studentIds.length === 0 || moduleIds.length === 0) {
    res.status(400).json({ error: "studentIds and moduleIds cannot be empty" });
    return;
  }

  // Verify all students exist
  const students = await db.query.users.findMany({
    where: inArray(users.id, studentIds),
  });

  if (students.length !== studentIds.length) {
    res.status(404).json({ error: "One or more students not found" });
    return;
  }

  // Verify all modules exist
  const modulesData = await db.query.modules.findMany({
    where: inArray(modules.id, moduleIds),
  });

  if (modulesData.length !== moduleIds.length) {
    res.status(404).json({ error: "One or more modules not found" });
    return;
  }

  // Create assignments
  const assignments = [];
  for (const studentId of studentIds) {
    for (const moduleId of moduleIds) {
      // Check if already assigned
      const existing = await db.query.moduleAssignments.findFirst({
        where: and(
          eq(moduleAssignments.studentId, studentId),
          eq(moduleAssignments.moduleId, moduleId)
        ),
      });

      if (!existing) {
        assignments.push({
          studentId,
          moduleId,
          assignedBy: req.user.id,
          status: "assigned" as const,
          dueDate: dueDate ? new Date(dueDate) : null,
          notes: notes || null,
          assignedAt: new Date(),
        });
      }
    }
  }

  if (assignments.length === 0) {
    res.status(409).json({ error: "All modules already assigned to specified students" });
    return;
  }

  const created = await db.insert(moduleAssignments).values(assignments).returning();

  await logAdmin(
    "admin.bulk_operation",
    req.user.id,
    {
      operation: "bulk_assign_modules",
      studentCount: studentIds.length,
      moduleCount: moduleIds.length,
      assignmentCount: created.length,
    },
    req
  );

  res.status(201).json({
    message: `Successfully assigned ${created.length} modules`,
    assignments: created,
  });
});
