import { eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { lessons } from "../core/database/schema/index.js";

type LessonCreateInput = {
  moduleId: number;
  title: string;
  content?: string;
  type: "text" | "video" | "diagram" | "pdf";
  videoUrl?: string | null;
  diagramUrl?: string | null;
  pdfUrl?: string | null;
  order: number;
};

type LessonUpdateInput = Partial<LessonCreateInput>;

export async function listLessons(moduleId?: number) {
  if (moduleId) {
    return db
      .select()
      .from(lessons)
      .where(eq(lessons.moduleId, moduleId))
      .orderBy(lessons.order);
  }
  return db.select().from(lessons).orderBy(lessons.order);
}

export async function getLessonById(id: number) {
  const [lesson] = await db.select().from(lessons).where(eq(lessons.id, id));
  return lesson ?? null;
}

export async function createLesson(payload: LessonCreateInput) {
  const [created] = await db.insert(lessons).values(payload).returning();
  return created;
}

export async function updateLesson(id: number, payload: LessonUpdateInput) {
  const [updated] = await db.update(lessons).set(payload).where(eq(lessons.id, id)).returning();
  return updated ?? null;
}
