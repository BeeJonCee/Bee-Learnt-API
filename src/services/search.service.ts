import { ilike, or } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { lessonResources, lessons, modules, subjects } from "../core/database/schema/index.js";

export async function searchAll(query: string) {
  const like = `%${query}%`;

  const [subjectRows, moduleRows, lessonRows, resourceRows] = await Promise.all([
    db
      .select()
      .from(subjects)
      .where(or(ilike(subjects.name, like), ilike(subjects.description, like))),
    db
      .select()
      .from(modules)
      .where(or(ilike(modules.title, like), ilike(modules.description, like))),
    db.select().from(lessons).where(ilike(lessons.title, like)),
    db
      .select()
      .from(lessonResources)
      .where(or(ilike(lessonResources.title, like), ilike(lessonResources.url, like))),
  ]);

  return {
    subjects: subjectRows,
    modules: moduleRows,
    lessons: lessonRows,
    resources: resourceRows,
  };
}
