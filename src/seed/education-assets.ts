import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

export type EducationAssetKind =
  | "teacher_guide"
  | "theory_chapter"
  | "practical_guide"
  | "caps_document"
  | "past_paper"
  | "memorandum"
  | "marking_guideline"
  | "answer_book"
  | "data_files"
  | "workbook"
  | "revision_guide"
  | "tutoring_guide"
  | "other";

export type EducationAssetCategory = "core_content" | "assessment" | "supporting";

type UpsertEducationAssetInput = {
  subjectId: number;
  gradeId?: number | null;
  chapterId?: number | null;
  kind: EducationAssetKind;
  category: EducationAssetCategory;
  title: string;
  sourceRelPath: string;
  sourceAbsPath?: string | null;
  mimeType?: string | null;
  fileSize?: number | null;
  language?: string | null;
  year?: number | null;
  session?: string | null;
  paperNumber?: number | null;
  metadata?: Record<string, unknown> | null;
  isAvailable?: boolean;
};

function normalizePath(value: string): string {
  return value.replace(/\\/g, "/");
}

function decodePathSegments(value: string): string {
  return value
    .split("/")
    .filter(Boolean)
    .map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        return segment;
      }
    })
    .join("/");
}

export function deriveSourceRelPath(input: {
  educationFolder: string;
  filePath?: string | null;
  fileUrl?: string | null;
}): string | null {
  const educationNorm = normalizePath(input.educationFolder).replace(/\/+$/, "");
  const filePathNorm = input.filePath ? normalizePath(input.filePath) : "";

  if (filePathNorm) {
    const marker = `${educationNorm}/`;
    if (filePathNorm.startsWith(marker)) {
      return filePathNorm.slice(marker.length);
    }
    const splitToken = "/Education/";
    const splitIndex = filePathNorm.indexOf(splitToken);
    if (splitIndex >= 0) {
      return filePathNorm.slice(splitIndex + splitToken.length);
    }
    return filePathNorm;
  }

  if (input.fileUrl) {
    return decodePathSegments(input.fileUrl);
  }

  return null;
}

export async function upsertEducationAsset(input: UpsertEducationAssetInput): Promise<number> {
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM education_assets
    WHERE source_rel_path = ${input.sourceRelPath}
  `);

  if (existing.rows[0]) {
    await db.execute(sql`
      UPDATE education_assets
      SET
        subject_id = ${input.subjectId},
        grade_id = ${input.gradeId ?? null},
        chapter_id = ${input.chapterId ?? null},
        kind = ${input.kind}::education_asset_kind,
        category = ${input.category}::education_asset_category,
        title = ${input.title},
        source_abs_path = ${input.sourceAbsPath ?? null},
        mime_type = ${input.mimeType ?? null},
        file_size = ${input.fileSize ?? null},
        language = ${input.language ?? "English"},
        year = ${input.year ?? null},
        session = ${input.session ?? null}::exam_session,
        paper_number = ${input.paperNumber ?? null},
        metadata = COALESCE(${input.metadata ?? null}::jsonb, metadata),
        is_available = ${input.isAvailable ?? true},
        updated_at = NOW()
      WHERE id = ${existing.rows[0].id}
    `);
    return existing.rows[0].id;
  }

  const created = await db.execute<{ id: number }>(sql`
    INSERT INTO education_assets (
      subject_id,
      grade_id,
      chapter_id,
      kind,
      category,
      source_rel_path,
      source_abs_path,
      title,
      mime_type,
      file_size,
      language,
      year,
      session,
      paper_number,
      metadata,
      is_available
    )
    VALUES (
      ${input.subjectId},
      ${input.gradeId ?? null},
      ${input.chapterId ?? null},
      ${input.kind}::education_asset_kind,
      ${input.category}::education_asset_category,
      ${input.sourceRelPath},
      ${input.sourceAbsPath ?? null},
      ${input.title},
      ${input.mimeType ?? null},
      ${input.fileSize ?? null},
      ${input.language ?? "English"},
      ${input.year ?? null},
      ${input.session ?? null}::exam_session,
      ${input.paperNumber ?? null},
      ${input.metadata ?? {}},
      ${input.isAvailable ?? true}
    )
    RETURNING id
  `);

  return created.rows[0].id;
}

export function resourceTypeToAssetKind(type: string): EducationAssetKind {
  switch (type) {
    case "teacher_guide":
      return "teacher_guide";
    case "practical_guide":
      return "practical_guide";
    case "caps_document":
      return "caps_document";
    case "learner_data":
      return "data_files";
    case "revision_guide":
      return "revision_guide";
    case "workbook":
      return "workbook";
    case "tutoring_guide":
      return "tutoring_guide";
    default:
      return "other";
  }
}

export function resourceTypeToAssetCategory(type: string): EducationAssetCategory {
  switch (type) {
    case "textbook":
    case "teacher_guide":
    case "practical_guide":
    case "caps_document":
      return "core_content";
    case "revision_guide":
    case "workbook":
    case "tutoring_guide":
      return "supporting";
    default:
      return "supporting";
  }
}

export function docTypeToAssetKind(type: string): EducationAssetKind {
  switch (type) {
    case "question_paper":
      return "past_paper";
    case "memorandum":
      return "memorandum";
    case "marking_guideline":
      return "marking_guideline";
    case "answer_book":
      return "answer_book";
    case "data_files":
      return "data_files";
    default:
      return "other";
  }
}

export function docTypeToAssetCategory(type: string): EducationAssetCategory {
  switch (type) {
    case "question_paper":
    case "memorandum":
    case "marking_guideline":
    case "answer_book":
    case "data_files":
      return "assessment";
    default:
      return "supporting";
  }
}
