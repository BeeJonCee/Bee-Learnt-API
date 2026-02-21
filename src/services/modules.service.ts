import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { modules } from "../core/database/schema/index.js";

type ModuleCreateInput = {
  subjectId: number;
  title: string;
  description?: string;
  grade: number;
  order: number;
  capsTags?: string[];
};

type ModuleUpdateInput = Partial<ModuleCreateInput>;

export async function listModules(subjectId?: number, grade?: number) {
  const conditions = [];
  if (subjectId) conditions.push(eq(modules.subjectId, subjectId));
  if (grade) conditions.push(eq(modules.grade, grade));

  if (conditions.length > 0) {
    return db
      .select()
      .from(modules)
      .where(and(...conditions))
      .orderBy(modules.order);
  }

  return db.select().from(modules).orderBy(modules.order);
}

export async function getModuleById(id: number) {
  const [moduleRow] = await db.select().from(modules).where(eq(modules.id, id));
  return moduleRow ?? null;
}

export async function createModule(payload: ModuleCreateInput) {
  const [created] = await db.insert(modules).values(payload).returning();
  return created;
}

export async function updateModule(id: number, payload: ModuleUpdateInput) {
  const [updated] = await db.update(modules).set(payload).where(eq(modules.id, id)).returning();
  return updated ?? null;
}

export async function deleteModule(id: number) {
  const [deleted] = await db.delete(modules).where(eq(modules.id, id)).returning();
  return deleted ?? null;
}
