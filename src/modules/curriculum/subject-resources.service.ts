import { and, eq } from "drizzle-orm";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { db } from "../../core/database/index.js";
import { subjectResources } from "../../core/database/schema/index.js";

interface SubjectResourceFilters {
  subjectId?: number;
  gradeId?: number;
  type?: string;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EDUCATION_FOLDER = path.resolve(__dirname, "../../Education");

function resolveEducationFilePath(filePath: string | null | undefined): string | null {
  if (!filePath) return null;
  if (path.isAbsolute(filePath)) return filePath;
  return path.join(EDUCATION_FOLDER, filePath);
}

function hasEducationFile(filePath: string | null | undefined): boolean {
  const resolved = resolveEducationFilePath(filePath);
  if (!resolved) return false;
  return fs.existsSync(resolved);
}

function resourceDownloadUrl(resourceId: number): string {
  return `/api/education/resources/${resourceId}/download`;
}

function withResourceDownloadInfo<T extends { id: number; filePath: string | null }>(resource: T) {
  const downloadUrl = resourceDownloadUrl(resource.id);
  return {
    ...resource,
    downloadUrl,
    isAvailable: hasEducationFile(resource.filePath),
  };
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

  const rows =
    conditions.length === 0
      ? await db.select().from(subjectResources)
      : await db
          .select()
          .from(subjectResources)
          .where(and(...conditions));

  return rows.map(withResourceDownloadInfo);
}

export async function getSubjectResourceById(id: number) {
  const [resource] = await db
    .select()
    .from(subjectResources)
    .where(eq(subjectResources.id, id));
  return resource ? withResourceDownloadInfo(resource) : null;
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
