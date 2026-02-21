import "dotenv/config";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

/**
 * NSC Papers Seeding Script
 *
 * Walks the Education folder and seeds:
 * - curricula
 * - grades
 * - subjects (if not existing)
 * - nsc_papers
 * - nsc_paper_documents
 */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EDUCATION_FOLDER = path.join(__dirname, "../../Education");

// ============ TYPE DEFINITIONS ============

interface ParsedFile {
  subject: string;
  grade: number;
  year: number;
  session: "november" | "may_june" | "february_march" | "supplementary" | "exemplar";
  paperNumber: number;
  language: string;
  docType: "question_paper" | "memorandum" | "marking_guideline" | "answer_book" | "data_files" | "addendum" | "formula_sheet";
  filePath: string;
  fileName: string;
}

// ============ FILE PARSING HELPERS ============

function normalizeSubject(rawSubject: string): string {
  return rawSubject.trim();
}

function parseGradeFromPath(filePath: string): number | null {
  // Match "Grade 10", "grade 12", "GR 12", etc.
  const gradeMatch = filePath.match(/grade\s*(\d+)|gr\s*(\d+)/i);
  if (gradeMatch) {
    return parseInt(gradeMatch[1] || gradeMatch[2], 10);
  }
  return null;
}

function parseSession(fileName: string, folderPath: string): ParsedFile["session"] {
  const lowerPath = (fileName + folderPath).toLowerCase();

  if (lowerPath.includes("exemplar")) {
    return "exemplar";
  }
  if (lowerPath.includes("supplementary") || lowerPath.includes("feb-march") || lowerPath.includes("february")) {
    return "february_march";
  }
  if (lowerPath.includes("may-june") || lowerPath.includes("mayjune") || lowerPath.includes("jun")) {
    return "may_june";
  }
  // Default to November for Nov or when no session specified
  return "november";
}

function parsePaperNumber(fileName: string): number {
  // Match P1, P2, Paper 1, Paper 2, etc.
  const paperMatch = fileName.match(/\bP(\d)\b|paper\s*(\d)/i);
  if (paperMatch) {
    return parseInt(paperMatch[1] || paperMatch[2], 10);
  }
  return 1; // Default to paper 1
}

function parseLanguage(fileName: string): string {
  const lower = fileName.toLowerCase();
  if (lower.includes("afr") && lower.includes("eng")) {
    return "English & Afrikaans";
  }
  if (lower.includes("afr")) {
    return "Afrikaans";
  }
  return "English";
}

function parseDocType(fileName: string): ParsedFile["docType"] {
  const lower = fileName.toLowerCase();
  const ext = path.extname(fileName).toLowerCase();

  // Data files
  if (lower.startsWith("data") || lower.includes("data files") || lower.includes("learner files")) {
    return "data_files";
  }
  if (ext === ".exe" || ext === ".zip") {
    return "data_files";
  }

  // Memorandum / Marking Guideline
  if (lower.includes(" mg ") || lower.includes("_mg_") || lower.includes(" mg.")) {
    return "marking_guideline";
  }
  if (lower.includes("memo")) {
    return "memorandum";
  }

  // Answer book
  if (lower.includes("answer book")) {
    return "answer_book";
  }

  // Formula sheet
  if (lower.includes("formula")) {
    return "formula_sheet";
  }

  // Addendum
  if (lower.includes("addendum")) {
    return "addendum";
  }

  // Default to question paper for PDFs and DOCXs
  return "question_paper";
}

function parseYear(filePath: string, fileName: string): number | null {
  // Try to find year in filename first
  const fileYearMatch = fileName.match(/\b(20\d{2})\b/);
  if (fileYearMatch) {
    return parseInt(fileYearMatch[1], 10);
  }

  // Try to find year in path (folder structure)
  const pathYearMatch = filePath.match(/\/(\d{4})\//);
  if (pathYearMatch) {
    return parseInt(pathYearMatch[1], 10);
  }

  // Try folder names like "2018-2019"
  const rangeMatch = filePath.match(/\/(\d{4})-\d{4}\//);
  if (rangeMatch) {
    return parseInt(rangeMatch[1], 10);
  }

  return null;
}

function parseFile(filePath: string, subject: string): ParsedFile | null {
  const fileName = path.basename(filePath);
  const ext = path.extname(fileName).toLowerCase();

  // Skip non-document files (Delphi project files, etc.)
  const validExtensions = [".pdf", ".docx", ".doc", ".exe", ".zip"];
  if (!validExtensions.includes(ext)) {
    return null;
  }

  // Skip study guides and revision materials (not NSC papers)
  const lower = fileName.toLowerCase();
  if (lower.includes("study_guide") || lower.includes("workbook") || lower.includes("tutoring") ||
      lower.includes("revision") || lower.includes("caps") || lower.includes("pat")) {
    return null;
  }

  const grade = parseGradeFromPath(filePath);
  const year = parseYear(filePath, fileName);

  if (!grade || !year) {
    console.log(`  Skipping (no grade/year): ${fileName}`);
    return null;
  }

  return {
    subject: normalizeSubject(subject),
    grade,
    year,
    session: parseSession(fileName, filePath),
    paperNumber: parsePaperNumber(fileName),
    language: parseLanguage(fileName),
    docType: parseDocType(fileName),
    filePath: filePath.replace(/\\/g, "/"),
    fileName,
  };
}

// ============ FILE SYSTEM HELPERS ============

function walkDirectory(dir: string, subject: string): ParsedFile[] {
  const results: ParsedFile[] = [];

  if (!fs.existsSync(dir)) {
    return results;
  }

  const items = fs.readdirSync(dir, { withFileTypes: true });

  for (const item of items) {
    const fullPath = path.join(dir, item.name);

    if (item.isDirectory()) {
      results.push(...walkDirectory(fullPath, subject));
    } else {
      const parsed = parseFile(fullPath, subject);
      if (parsed) {
        results.push(parsed);
      }
    }
  }

  return results;
}

// ============ DATABASE HELPERS ============

async function ensureCurriculum(): Promise<number> {
  // Check if CAPS curriculum exists
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM curricula WHERE name = 'CAPS' AND country = 'South Africa'
  `);

  if (existing.rows[0]) {
    return existing.rows[0].id;
  }

  // Create CAPS curriculum
  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO curricula (name, country, description)
    VALUES ('CAPS', 'South Africa', 'Curriculum and Assessment Policy Statement')
    RETURNING id
  `);

  return inserted.rows[0].id;
}

async function ensureGrade(curriculumId: number, level: number): Promise<number> {
  const label = `Grade ${level}`;

  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM grades WHERE curriculum_id = ${curriculumId} AND level = ${level}
  `);

  if (existing.rows[0]) {
    return existing.rows[0].id;
  }

  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO grades (curriculum_id, level, label)
    VALUES (${curriculumId}, ${level}, ${label})
    RETURNING id
  `);

  return inserted.rows[0].id;
}

async function ensureSubject(name: string): Promise<number> {
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM subjects WHERE name = ${name}
  `);

  if (existing.rows[0]) {
    return existing.rows[0].id;
  }

  // Create subject with a code
  const code = name.substring(0, 3).toUpperCase();
  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO subjects (name, code, description, is_active)
    VALUES (${name}, ${code}, ${`${name} - NSC Subject`}, true)
    RETURNING id
  `);

  return inserted.rows[0].id;
}

async function ensureNscPaper(
  subjectId: number,
  gradeId: number | null,
  year: number,
  session: string,
  paperNumber: number,
  language: string
): Promise<number> {
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM nsc_papers
    WHERE subject_id = ${subjectId}
      AND year = ${year}
      AND session = ${session}::exam_session
      AND paper_number = ${paperNumber}
      AND language = ${language}
  `);

  if (existing.rows[0]) {
    return existing.rows[0].id;
  }

  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO nsc_papers (subject_id, grade_id, year, session, paper_number, language)
    VALUES (${subjectId}, ${gradeId}, ${year}, ${session}::exam_session, ${paperNumber}, ${language})
    RETURNING id
  `);

  return inserted.rows[0].id;
}

async function ensureNscPaperDocument(
  nscPaperId: number,
  docType: string,
  title: string,
  fileUrl: string,
  filePath: string,
  language: string
): Promise<void> {
  // Check if document already exists
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM nsc_paper_documents
    WHERE nsc_paper_id = ${nscPaperId} AND file_path = ${filePath}
  `);

  if (existing.rows[0]) {
    return; // Already exists
  }

  // Get file size
  let fileSize: number | null = null;
  try {
    const stats = fs.statSync(filePath);
    fileSize = stats.size;
  } catch {
    // Ignore if file not accessible
  }

  // Determine mime type
  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes: Record<string, string> = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".doc": "application/msword",
    ".zip": "application/zip",
    ".exe": "application/x-msdownload",
  };
  const mimeType = mimeTypes[ext] || "application/octet-stream";

  await db.execute(sql`
    INSERT INTO nsc_paper_documents (nsc_paper_id, doc_type, title, file_url, file_path, file_size, mime_type, language)
    VALUES (
      ${nscPaperId},
      ${docType}::paper_doc_type,
      ${title},
      ${fileUrl},
      ${filePath},
      ${fileSize},
      ${mimeType},
      ${language}
    )
  `);
}

// ============ MAIN SEEDING FUNCTION ============

async function seedNscPapers() {
  console.log("Starting NSC Papers seeding...\n");
  console.log(`Education folder: ${EDUCATION_FOLDER}`);

  if (!fs.existsSync(EDUCATION_FOLDER)) {
    console.error("Education folder not found!");
    process.exit(1);
  }

  // Ensure CAPS curriculum exists
  const curriculumId = await ensureCurriculum();
  console.log(`CAPS Curriculum ID: ${curriculumId}`);

  // Get all subject folders
  const subjectFolders = fs.readdirSync(EDUCATION_FOLDER, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => d.name);

  console.log(`Found subjects: ${subjectFolders.join(", ")}\n`);

  const stats = {
    subjectsProcessed: 0,
    papersCreated: 0,
    documentsCreated: 0,
    filesSkipped: 0,
  };

  // Maps to track created records
  const gradeCache = new Map<number, number>();

  for (const subjectName of subjectFolders) {
    console.log(`\n=== Processing Subject: ${subjectName} ===`);

    const subjectId = await ensureSubject(subjectName);
    console.log(`Subject ID: ${subjectId}`);
    stats.subjectsProcessed++;

    const subjectPath = path.join(EDUCATION_FOLDER, subjectName);
    const files = walkDirectory(subjectPath, subjectName);

    console.log(`Found ${files.length} valid document files`);

    // Group files by paper (subject + year + session + paper number + language)
    const paperGroups = new Map<string, ParsedFile[]>();

    for (const file of files) {
      const key = `${file.subject}|${file.year}|${file.session}|${file.paperNumber}|${file.language}`;
      if (!paperGroups.has(key)) {
        paperGroups.set(key, []);
      }
      paperGroups.get(key)!.push(file);
    }

    console.log(`Grouped into ${paperGroups.size} unique papers`);

    // Process each paper group
    for (const [key, paperFiles] of paperGroups) {
      const sample = paperFiles[0];

      // Ensure grade exists
      let gradeId: number | null = null;
      if (sample.grade) {
        if (gradeCache.has(sample.grade)) {
          gradeId = gradeCache.get(sample.grade)!;
        } else {
          gradeId = await ensureGrade(curriculumId, sample.grade);
          gradeCache.set(sample.grade, gradeId);
        }
      }

      // Create or get NSC paper record
      const nscPaperId = await ensureNscPaper(
        subjectId,
        gradeId,
        sample.year,
        sample.session,
        sample.paperNumber,
        sample.language
      );

      stats.papersCreated++;

      // Add all documents for this paper
      for (const file of paperFiles) {
        // Store the path relative to Education folder, preserving the nested hierarchy
        const normalizedEducation = EDUCATION_FOLDER.replace(/\\/g, "/");
        const relativeUrl = file.filePath
          .replace(normalizedEducation, "")
          .split("/")
          .filter(Boolean)
          .map(segment => encodeURIComponent(segment))
          .join("/");

        await ensureNscPaperDocument(
          nscPaperId,
          file.docType,
          file.fileName,
          relativeUrl,
          file.filePath,
          file.language
        );

        stats.documentsCreated++;
        console.log(`  + ${file.docType}: ${file.fileName}`);
      }
    }
  }

  console.log("\n=== Seeding Complete ===");
  console.log(`Subjects processed: ${stats.subjectsProcessed}`);
  console.log(`Papers created/updated: ${stats.papersCreated}`);
  console.log(`Documents created: ${stats.documentsCreated}`);
}

// ============ RUN ============

seedNscPapers().catch((error) => {
  console.error("Seeding failed:", error);
  process.exit(1);
});
