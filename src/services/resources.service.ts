import { eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { lessonResources } from "../core/database/schema/index.js";

type ResourceCreateInput = {
  lessonId: number;
  title: string;
  type: "pdf" | "link" | "video" | "diagram";
  url: string;
  tags?: string[];
};

export async function listResources(lessonId?: number) {
  if (lessonId) {
    return db
      .select()
      .from(lessonResources)
      .where(eq(lessonResources.lessonId, lessonId));
  }
  return db.select().from(lessonResources);
}

export async function getResourceById(id: number) {
  const [resource] = await db
    .select()
    .from(lessonResources)
    .where(eq(lessonResources.id, id));
  return resource ?? null;
}

export async function createResource(payload: ResourceCreateInput) {
  const [created] = await db.insert(lessonResources).values(payload).returning();
  return created;
}
