import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { checklistProgress, moduleChecklistItems } from "../core/database/schema/index.js";

export async function listChecklistItems(moduleId: number, userId: string) {
  const rows = await db
    .select({
      id: moduleChecklistItems.id,
      title: moduleChecklistItems.title,
      order: moduleChecklistItems.order,
      required: moduleChecklistItems.required,
      completed: checklistProgress.completed,
      completedAt: checklistProgress.completedAt,
    })
    .from(moduleChecklistItems)
    .leftJoin(
      checklistProgress,
      and(
        eq(checklistProgress.itemId, moduleChecklistItems.id),
        eq(checklistProgress.userId, userId)
      )
    )
    .where(eq(moduleChecklistItems.moduleId, moduleId))
    .orderBy(moduleChecklistItems.order);

  return rows.map((row) => ({
    id: row.id,
    title: row.title,
    order: row.order,
    required: row.required,
    completed: row.completed ?? false,
    completedAt: row.completedAt,
  }));
}

export async function upsertChecklistProgress(
  userId: string,
  itemId: number,
  completed: boolean
) {
  const [existing] = await db
    .select()
    .from(checklistProgress)
    .where(and(eq(checklistProgress.userId, userId), eq(checklistProgress.itemId, itemId)));

  if (existing) {
    const [updated] = await db
      .update(checklistProgress)
      .set({
        completed,
        completedAt: completed ? new Date() : null,
      })
      .where(eq(checklistProgress.id, existing.id))
      .returning();
    return { record: updated, created: false };
  }

  const [created] = await db
    .insert(checklistProgress)
    .values({
      userId,
      itemId,
      completed,
      completedAt: completed ? new Date() : null,
    })
    .returning();

  return { record: created, created: true };
}
