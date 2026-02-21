import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { subjectResources } from "../core/database/schema/index.js";

interface SubjectResourceFilters {
  subjectId?: number;
  gradeId?: number;
  type?: string;
}

export async function listSubjectResources(filters: SubjectResourceFilters) {
  const conditions = [];

  if (filters.subjectId) {
    conditions.push(eq(subjectResources.subjectId, filters.subjectId));
  }
  if (filters.gradeId) {
    conditions.push(eq(subjectResources.gradeId, filters.gradeId));
  }
  if (filters.type) {
    conditions.push(eq(subjectResources.type, filters.type as any));
  }

  if (conditions.length === 0) {
    return db.select().from(subjectResources);
  }

  return db
    .select()
    .from(subjectResources)
    .where(and(...conditions));
}

export async function getSubjectResourceById(id: number) {
  const [resource] = await db
    .select()
    .from(subjectResources)
    .where(eq(subjectResources.id, id));
  return resource ?? null;
}

export async function createSubjectResource(payload: typeof subjectResources.$inferInsert) {
  const [created] = await db.insert(subjectResources).values(payload).returning();
  return created;
}

export async function deleteSubjectResource(id: number) {
  const [deleted] = await db
    .delete(subjectResources)
    .where(eq(subjectResources.id, id))
    .returning({ id: subjectResources.id });
  return deleted ?? null;
}
