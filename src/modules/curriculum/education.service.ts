import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { and, eq } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import {
  educationAssets,
  grades,
  nscPaperDocuments,
  subjectResources,
  subjects,
} from "../../core/database/schema/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EDUCATION_FOLDER = path.resolve(__dirname, "../../Education");

/**
 * Resolve a file_path from the database to an absolute filesystem path.
 * Handles both absolute paths and paths relative to the Education folder.
 */
function resolveFilePath(filePath: string): string {
  if (path.isAbsolute(filePath)) {
    return filePath;
  }
  return path.join(EDUCATION_FOLDER, filePath);
}

export async function getNscDocumentFile(documentId: number) {
  const [doc] = await db
    .select({
      id: nscPaperDocuments.id,
      title: nscPaperDocuments.title,
      filePath: nscPaperDocuments.filePath,
      mimeType: nscPaperDocuments.mimeType,
    })
    .from(nscPaperDocuments)
    .where(eq(nscPaperDocuments.id, documentId));

  if (!doc || !doc.filePath) return null;

  const absolutePath = resolveFilePath(doc.filePath);
  if (!fs.existsSync(absolutePath)) return null;

  return {
    absolutePath,
    fileName: doc.title,
    mimeType: doc.mimeType || "application/octet-stream",
  };
}

export async function getSubjectResourceFile(resourceId: number) {
  const [resource] = await db
    .select({
      id: subjectResources.id,
      title: subjectResources.title,
      filePath: subjectResources.filePath,
      mimeType: subjectResources.mimeType,
    })
    .from(subjectResources)
    .where(eq(subjectResources.id, resourceId));

  if (!resource || !resource.filePath) return null;

  const absolutePath = resolveFilePath(resource.filePath);
  if (!fs.existsSync(absolutePath)) return null;

  return {
    absolutePath,
    fileName: resource.title,
    mimeType: resource.mimeType || "application/octet-stream",
  };
}

interface EducationAssetListFilters {
  subjectId?: number;
  gradeId?: number;
  category?: "core_content" | "assessment" | "supporting";
}

export async function listEducationAssets(filters: EducationAssetListFilters) {
  const conditions = [];
  if (filters.subjectId) conditions.push(eq(educationAssets.subjectId, filters.subjectId));
  if (filters.gradeId) conditions.push(eq(educationAssets.gradeId, filters.gradeId));
  if (filters.category) conditions.push(eq(educationAssets.category, filters.category));

  let query = db
    .select({
      id: educationAssets.id,
      subjectId: educationAssets.subjectId,
      subjectName: subjects.name,
      gradeId: educationAssets.gradeId,
      gradeLabel: grades.label,
      kind: educationAssets.kind,
      category: educationAssets.category,
      title: educationAssets.title,
      sourceRelPath: educationAssets.sourceRelPath,
      mimeType: educationAssets.mimeType,
      fileSize: educationAssets.fileSize,
      language: educationAssets.language,
      year: educationAssets.year,
      session: educationAssets.session,
      paperNumber: educationAssets.paperNumber,
      isAvailable: educationAssets.isAvailable,
      createdAt: educationAssets.createdAt,
      updatedAt: educationAssets.updatedAt,
    })
    .from(educationAssets)
    .$dynamic()
    .innerJoin(subjects, eq(educationAssets.subjectId, subjects.id))
    .leftJoin(grades, eq(educationAssets.gradeId, grades.id))
    .orderBy(subjects.name, educationAssets.gradeId, educationAssets.kind, educationAssets.title);

  if (conditions.length) {
    query = query.where(and(...conditions));
  }

  const rows = await query;

  return rows.map((row) => ({
    ...row,
    downloadUrl: `/api/education/assets/${row.id}/download`,
  }));
}

export async function getEducationAssetFile(assetId: number) {
  const [asset] = await db
    .select({
      id: educationAssets.id,
      title: educationAssets.title,
      sourceAbsPath: educationAssets.sourceAbsPath,
      sourceRelPath: educationAssets.sourceRelPath,
      mimeType: educationAssets.mimeType,
    })
    .from(educationAssets)
    .where(eq(educationAssets.id, assetId));

  if (!asset) return null;

  const candidatePath = asset.sourceAbsPath || asset.sourceRelPath;
  if (!candidatePath) return null;

  const absolutePath = resolveFilePath(candidatePath);
  if (!fs.existsSync(absolutePath)) return null;

  return {
    absolutePath,
    fileName: asset.title,
    mimeType: asset.mimeType || "application/octet-stream",
  };
}
