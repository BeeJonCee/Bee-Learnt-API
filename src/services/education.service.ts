import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { nscPaperDocuments, subjectResources } from "../core/database/schema/index.js";

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
