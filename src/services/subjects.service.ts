import { eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { modules, subjects } from "../core/database/schema/index.js";

export async function listSubjects() {
  return db.select().from(subjects).orderBy(subjects.name);
}

export async function getSubjectById(id: number) {
  const [subject] = await db.select().from(subjects).where(eq(subjects.id, id));
  return subject ?? null;
}

export async function listModulesForSubject(subjectId: number) {
  return db.select().from(modules).where(eq(modules.subjectId, subjectId));
}

type SubjectCreateInput = {
  name: string;
  description?: string;
  minGrade: number;
  maxGrade: number;
};

type SubjectUpdateInput = Partial<SubjectCreateInput>;

export async function createSubject(payload: SubjectCreateInput) {
  const [created] = await db.insert(subjects).values(payload).returning();
  return created;
}

export async function updateSubject(id: number, payload: SubjectUpdateInput) {
  const [updated] = await db
    .update(subjects)
    .set(payload)
    .where(eq(subjects.id, id))
    .returning();
  return updated ?? null;
}
