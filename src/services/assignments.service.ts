import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { assignments } from "../core/database/schema/index.js";

type AssignmentCreateInput = {
  moduleId: number;
  lessonId?: number;
  title: string;
  description?: string;
  dueDate: string;
  priority?: "low" | "medium" | "high";
  status?: "todo" | "in_progress" | "submitted" | "graded";
  grade: number;
};

type AssignmentUpdateInput = Partial<AssignmentCreateInput>;

export async function listAssignments(moduleId?: number, grade?: number) {
  if (moduleId && grade) {
    return db
      .select()
      .from(assignments)
      .where(and(eq(assignments.moduleId, moduleId), eq(assignments.grade, grade)))
      .orderBy(assignments.dueDate);
  }

  if (moduleId) {
    return db
      .select()
      .from(assignments)
      .where(eq(assignments.moduleId, moduleId))
      .orderBy(assignments.dueDate);
  }

  if (grade) {
    return db
      .select()
      .from(assignments)
      .where(eq(assignments.grade, grade))
      .orderBy(assignments.dueDate);
  }

  return db.select().from(assignments).orderBy(assignments.dueDate);
}

export async function getAssignmentById(id: number) {
  const [assignment] = await db
    .select()
    .from(assignments)
    .where(eq(assignments.id, id));
  return assignment ?? null;
}

export async function createAssignment(payload: AssignmentCreateInput, createdBy?: string) {
  const [created] = await db
    .insert(assignments)
    .values({
      ...payload,
      dueDate: new Date(payload.dueDate),
      createdBy,
    })
    .returning();
  return created;
}

export async function updateAssignment(id: number, payload: AssignmentUpdateInput) {
  const updates = {
    ...payload,
    dueDate: payload.dueDate ? new Date(payload.dueDate) : undefined,
  };

  const [updated] = await db
    .update(assignments)
    .set(updates)
    .where(eq(assignments.id, id))
    .returning();
  return updated ?? null;
}
