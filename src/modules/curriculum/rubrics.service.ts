import { eq } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import { rubrics } from "../../core/database/schema/index.js";
import type { RubricCriterion } from "../../core/database/schema/index.js";

type RubricCreateInput = {
  title: string;
  subjectId?: number;
  criteria: RubricCriterion[];
};

type RubricUpdateInput = Partial<RubricCreateInput>;

export async function listRubrics(subjectId?: number) {
  if (subjectId) {
    return db
      .select()
      .from(rubrics)
      .where(eq(rubrics.subjectId, subjectId))
      .orderBy(rubrics.createdAt);
  }
  return db.select().from(rubrics).orderBy(rubrics.createdAt);
}

export async function getRubricById(id: number) {
  const [rubric] = await db.select().from(rubrics).where(eq(rubrics.id, id));
  return rubric ?? null;
}

export async function createRubric(payload: RubricCreateInput, createdBy?: string) {
  const [created] = await db
    .insert(rubrics)
    .values({ ...payload, createdBy })
    .returning();
  return created;
}

export async function updateRubric(id: number, payload: RubricUpdateInput) {
  const [updated] = await db
    .update(rubrics)
    .set(payload)
    .where(eq(rubrics.id, id))
    .returning();
  return updated ?? null;
}
