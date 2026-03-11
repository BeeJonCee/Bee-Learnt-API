import "dotenv/config";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import {
  deriveSourceRelPath,
  docTypeToAssetCategory,
  docTypeToAssetKind,
  upsertEducationAsset,
} from "./education-assets.js";

/**
 * NSC Papers Seeding Script
 *
 * Walks the Education folder and seeds:
 *   curricula → grades → subjects → nsc_papers → nsc_paper_documents
 *
 * Education folder layout expected:
 *   Education/
 *     Information Technology/
 *       Grade 10/
 *       Grade 11/
 *       Grade 12/
 *         TextBook/
 *         Examplars/2018/
 *         Past Papers/2018..2025/
 *         Supplementary Exams/2018-2019/
 *     Mathematics/
 *       Grade 10/
 *         2015/ 2016/ 2017/ 2018/
 */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EDUCATION_FOLDER = path.join(__dirname, "../Education");

// ─── Known paper specifications ──────────────────────────────────────────────
// Key: "Subject|grade|paperNumber"

const PAPER_SPECS: Record<string, { totalMarks: number; durationMinutes: number }> = {
  // Information Technology NSC
  "Information Technology|12|1": { totalMarks: 150, durationMinutes: 120 },
  "Information Technology|12|2": { totalMarks: 150, durationMinutes: 180 },
  "Information Technology|11|1": { totalMarks: 120, durationMinutes: 120 },
  "Information Technology|11|2": { totalMarks: 150, durationMinutes: 180 },
  "Information Technology|10|1": { totalMarks: 120, durationMinutes: 120 },
  "Information Technology|10|2": { totalMarks: 120, durationMinutes: 120 },
  // Mathematics NSC
  "Mathematics|12|1": { totalMarks: 150, durationMinutes: 180 },
  "Mathematics|12|2": { totalMarks: 150, durationMinutes: 180 },
  "Mathematics|11|1": { totalMarks: 150, durationMinutes: 180 },
  "Mathematics|11|2": { totalMarks: 150, durationMinutes: 180 },
  "Mathematics|10|1": { totalMarks: 100, durationMinutes: 120 },
  "Mathematics|10|2": { totalMarks: 100, durationMinutes: 120 },
};

// ─── Types ────────────────────────────────────────────────────────────────────

type ExamSession = "november" | "may_june" | "february_march" | "supplementary" | "exemplar";
type DocType = "question_paper" | "memorandum" | "marking_guideline" | "answer_book" | "data_files" | "addendum" | "formula_sheet";

interface ParsedFile {
  subject: string;
  grade: number;
  year: number;
  session: ExamSession;
  paperNumber: number;
  language: string;
  docType: DocType;
  filePath: string;   // forward-slash normalised absolute path
  fileName: string;
}

type SampleQuestion = {
  questionNumber: string;
  questionText: string;
  marks: number;
  sectionLabel?: string;
  memoText?: string;
};

type SampleDocument = {
  docType: DocType;
  title: string;
  fileUrl: string;
  filePath: string;
  language?: string;
};

type SamplePaper = {
  subject: string;
  grade: number;
  year: number;
  session: ExamSession;
  paperNumber: number;
  language: string;
  totalMarks?: number;
  durationMinutes?: number;
  documents: SampleDocument[];
  questions: SampleQuestion[];
};

// ─── Fallback sample data (used when Education folder absent) ─────────────────

const SAMPLE_PAPERS: SamplePaper[] = [
  {
    subject: "Mathematics",
    grade: 12,
    year: 2024,
    session: "november",
    paperNumber: 1,
    language: "English",
    totalMarks: 150,
    durationMinutes: 180,
    documents: [
      {
        docType: "question_paper",
        title: "Mathematics Grade 12 P1 November 2024 Question Paper",
        fileUrl: "samples/nsc/mathematics/2024/november/p1-question-paper.pdf",
        filePath: "samples/nsc/mathematics/2024/november/p1-question-paper.pdf",
      },
      {
        docType: "memorandum",
        title: "Mathematics Grade 12 P1 November 2024 Memorandum",
        fileUrl: "samples/nsc/mathematics/2024/november/p1-memorandum.pdf",
        filePath: "samples/nsc/mathematics/2024/november/p1-memorandum.pdf",
      },
    ],
    questions: [
      { questionNumber: "1.1", questionText: "Solve for x: 2x + 7 = 31.", marks: 2, sectionLabel: "Algebra", memoText: "x = 12" },
      { questionNumber: "2.1", questionText: "Determine the equation of the straight line passing through (2, 5) and (6, 13).", marks: 4, sectionLabel: "Functions", memoText: "Gradient m = 2, equation y = 2x + 1." },
      { questionNumber: "3.1", questionText: "Find the derivative of f(x) = 3x² - 4x + 9 and evaluate f'(2).", marks: 4, sectionLabel: "Calculus", memoText: "f'(x) = 6x - 4, so f'(2) = 8." },
      { questionNumber: "4.1", questionText: "A geometric sequence has first term 5 and common ratio 2. Write down the first four terms.", marks: 3, sectionLabel: "Sequences", memoText: "5, 10, 20, 40." },
      { questionNumber: "5.1", questionText: "Given P(A) = 0.4, P(B) = 0.3 and P(A and B) = 0.1, calculate P(A or B).", marks: 3, sectionLabel: "Probability", memoText: "P(A or B) = 0.4 + 0.3 - 0.1 = 0.6." },
    ],
  },
  {
    subject: "Mathematics",
    grade: 12,
    year: 2024,
    session: "november",
    paperNumber: 2,
    language: "English",
    totalMarks: 150,
    durationMinutes: 180,
    documents: [
      {
        docType: "question_paper",
        title: "Mathematics Grade 12 P2 November 2024 Question Paper",
        fileUrl: "samples/nsc/mathematics/2024/november/p2-question-paper.pdf",
        filePath: "samples/nsc/mathematics/2024/november/p2-question-paper.pdf",
      },
      {
        docType: "memorandum",
        title: "Mathematics Grade 12 P2 November 2024 Memorandum",
        fileUrl: "samples/nsc/mathematics/2024/november/p2-memorandum.pdf",
        filePath: "samples/nsc/mathematics/2024/november/p2-memorandum.pdf",
      },
    ],
    questions: [
      { questionNumber: "1.1", questionText: "Calculate the missing side in a right triangle where hypotenuse is 13 and one side is 5.", marks: 3, sectionLabel: "Trigonometry", memoText: "Using Pythagoras: side = √(13² − 5²) = 12." },
      { questionNumber: "2.1", questionText: "Find the area of a triangle with sides 8 and 10 and included angle 30°.", marks: 4, sectionLabel: "Trigonometry", memoText: "Area = ½ × 8 × 10 × sin30° = 20 square units." },
      { questionNumber: "3.1", questionText: "Determine the equation of the circle with centre (2, −1) and radius 5.", marks: 3, sectionLabel: "Analytical Geometry", memoText: "(x − 2)² + (y + 1)² = 25." },
    ],
  },
  {
    subject: "Information Technology",
    grade: 12,
    year: 2023,
    session: "may_june",
    paperNumber: 1,
    language: "English",
    totalMarks: 150,
    durationMinutes: 120,
    documents: [
      {
        docType: "question_paper",
        title: "Information Technology Grade 12 P1 May/June 2023 Question Paper",
        fileUrl: "samples/nsc/information-technology/2023/may-june/p1-question-paper.pdf",
        filePath: "samples/nsc/information-technology/2023/may-june/p1-question-paper.pdf",
      },
      {
        docType: "memorandum",
        title: "Information Technology Grade 12 P1 May/June 2023 Memorandum",
        fileUrl: "samples/nsc/information-technology/2023/may-june/p1-memorandum.pdf",
        filePath: "samples/nsc/information-technology/2023/may-june/p1-memorandum.pdf",
      },
      {
        docType: "data_files",
        title: "Information Technology Grade 12 P1 May/June 2023 Data Files",
        fileUrl: "samples/nsc/information-technology/2023/may-june/p1-data-files.zip",
        filePath: "samples/nsc/information-technology/2023/may-june/p1-data-files.zip",
      },
    ],
    questions: [
      { questionNumber: "1.1", questionText: "Write a SQL query to return all students with marks greater than 80 from the Results table.", marks: 5, sectionLabel: "Database", memoText: "SELECT * FROM Results WHERE mark > 80;" },
      { questionNumber: "2.1", questionText: "Explain the difference between a while loop and a for loop in programming.", marks: 4, sectionLabel: "Programming", memoText: "A for loop is used when the number of iterations is known. A while loop tests a condition each iteration." },
      { questionNumber: "3.1", questionText: "What is encapsulation in object-oriented programming?", marks: 3, sectionLabel: "OOP", memoText: "Encapsulation bundles data and methods in a class and restricts direct access to internal state." },
    ],
  },
];

// ─── File parsing ─────────────────────────────────────────────────────────────

// File extensions that represent exam documents
const VALID_EXTENSIONS = new Set([".pdf", ".docx", ".doc", ".zip", ".exe"]);

// Patterns in filenames that indicate non-exam material (textbooks, guides, etc.)
const SKIP_PATTERNS = [
  /\b(lb|lh)\b/i,              // Learner Book / Learner Handout codes
  /-LB[-_]/i,                  // e.g. Gr10_IT-Theory-LB-Print
  /learner[_\s-]?book/i,
  /teacher[_\s-]?guide/i,
  /teacher['s\s]*guide/i,
  /\bpat\b/i,                  // Practical Assessment Task
  /study[_\s-]?guide/i,
  /workbook/i,
  /revision/i,
  /tutoring/i,
  /full[_\s-]?revision/i,
  /term\d[_\s-]study/i,
  /\bcaps\b/i,
  /teacher['s]*\s/i,
];

function shouldSkipFile(fileName: string): boolean {
  return SKIP_PATTERNS.some(re => re.test(fileName));
}

/**
 * Skip files that live inside extracted data archive folders
 * (e.g. DataJUN2025/, DataENGNov2019/ — these are Delphi project trees,
 *  not standalone exam documents; the parent .exe archive is what gets seeded).
 */
function shouldSkipByPath(normalizedPath: string): boolean {
  return /\/Data(?:ENG|JUN|Jun)[A-Za-z]*\d{4}\//.test(normalizedPath);
}

/** Normalise to forward-slash path — must be called before any path parsing */
function normalizePath(p: string): string {
  return p.replace(/\\/g, "/");
}

function parseGradeFromPath(normalizedPath: string): number | null {
  const m = normalizedPath.match(/grade\s*(\d+)|\/gr\s*(\d+)\//i);
  if (m) return parseInt(m[1] ?? m[2], 10);
  return null;
}

function parseYear(normalizedPath: string, fileName: string): number | null {
  // Year in filename takes precedence (e.g. "Nov 2018 Eng")
  const fileYear = fileName.match(/\b(20\d{2})\b/);
  if (fileYear) return parseInt(fileYear[1], 10);

  // Year as a folder segment: .../2018/...
  const folderYear = normalizedPath.match(/\/(\d{4})\//);
  if (folderYear) return parseInt(folderYear[1], 10);

  // Year-range folder: .../2018-2019/...
  const rangeYear = normalizedPath.match(/\/(\d{4})-\d{4}\//);
  if (rangeYear) return parseInt(rangeYear[1], 10);

  return null;
}

function parseSession(normalizedPath: string, fileName: string): ExamSession {
  const combined = (normalizedPath + "/" + fileName).toLowerCase();

  if (combined.includes("exemplar")) return "exemplar";
  if (
    combined.includes("supplementary") ||
    combined.includes("feb-march") ||
    combined.includes("february_march") ||
    combined.includes("feb/march") ||
    /\bfeb\b/.test(combined)
  ) return "february_march";
  if (
    combined.includes("may-june") ||
    combined.includes("may_june") ||
    combined.includes("may/june") ||
    combined.includes("mayjune") ||
    combined.includes("june") ||
    /\bjun\b/.test(combined)
  ) return "may_june";

  // "Nov" or "November" → november (also the default)
  return "november";
}

function parsePaperNumber(fileName: string): number {
  const m = fileName.match(/\bP(\d)\b|paper\s*(\d)/i);
  if (m) return parseInt(m[1] ?? m[2], 10);
  return 1;
}

function parseLanguage(fileName: string): string {
  const lower = fileName.toLowerCase();
  if (lower.includes("afr") && lower.includes("eng")) return "English & Afrikaans";
  if (lower.includes("afr")) return "Afrikaans";
  return "English";
}

function parseDocType(fileName: string): DocType {
  const lower = fileName.toLowerCase();
  const ext = path.extname(fileName).toLowerCase();

  // Data / learner files first (ZIPs and EXEs are always data files)
  if (ext === ".zip" || ext === ".exe") return "data_files";
  if (/\bdata\b/.test(lower) || lower.includes("learner files") || lower.includes("data files")) {
    return "data_files";
  }

  // Marking guideline (MG marker)
  if (/[\s_\-]mg[\s_\-.]/.test(lower) || lower.includes("marking guide")) {
    return "marking_guideline";
  }

  // Memorandum
  if (lower.includes("memo")) return "memorandum";

  // Answer book
  if (lower.includes("answer book") || lower.includes("answerbook")) return "answer_book";

  // Formula sheet
  if (lower.includes("formula")) return "formula_sheet";

  // Addendum
  if (lower.includes("addendum")) return "addendum";

  return "question_paper";
}

/** Build a human-readable document title */
function buildTitle(parsed: ParsedFile): string {
  const SESSION_LABELS: Record<ExamSession, string> = {
    november: "November",
    may_june: "May/June",
    february_march: "Feb/March",
    supplementary: "Supplementary",
    exemplar: "Exemplar",
  };
  const DOC_LABELS: Record<DocType, string> = {
    question_paper:   "Question Paper",
    memorandum:       "Memorandum",
    marking_guideline:"Marking Guideline",
    answer_book:      "Answer Book",
    data_files:       "Data Files",
    addendum:         "Addendum",
    formula_sheet:    "Formula Sheet",
  };

  const session = SESSION_LABELS[parsed.session];
  const docLabel = DOC_LABELS[parsed.docType];
  const langSuffix = parsed.language !== "English" ? ` (${parsed.language})` : "";
  return `${parsed.subject} Grade ${parsed.grade} P${parsed.paperNumber} ${session} ${parsed.year} ${docLabel}${langSuffix}`;
}

function parseFile(rawFilePath: string, subject: string): ParsedFile | null {
  const filePath = normalizePath(rawFilePath);
  const fileName = path.basename(filePath);
  const ext = path.extname(fileName).toLowerCase();

  if (!VALID_EXTENSIONS.has(ext)) return null;
  if (shouldSkipFile(fileName)) return null;
  if (shouldSkipByPath(filePath)) return null;

  const grade = parseGradeFromPath(filePath);
  const year  = parseYear(filePath, fileName);

  if (!grade || !year) {
    console.log(`  Skipping (no grade/year): ${fileName}`);
    return null;
  }

  return {
    subject: subject.trim(),
    grade,
    year,
    session:     parseSession(filePath, fileName),
    paperNumber: parsePaperNumber(fileName),
    language:    parseLanguage(fileName),
    docType:     parseDocType(fileName),
    filePath,
    fileName,
  };
}

// ─── Directory walker ─────────────────────────────────────────────────────────

function walkDirectory(dir: string, subject: string): ParsedFile[] {
  if (!fs.existsSync(dir)) return [];

  const results: ParsedFile[] = [];

  for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, item.name);
    if (item.isDirectory()) {
      results.push(...walkDirectory(fullPath, subject));
    } else {
      const parsed = parseFile(fullPath, subject);
      if (parsed) results.push(parsed);
    }
  }

  return results;
}

// ─── Database helpers ─────────────────────────────────────────────────────────

async function ensureCurriculum(): Promise<number> {
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM curricula WHERE name = 'CAPS' AND country = 'South Africa'
  `);
  if (existing.rows[0]) return existing.rows[0].id;

  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO curricula (name, country, description)
    VALUES ('CAPS', 'South Africa', 'Curriculum and Assessment Policy Statement')
    RETURNING id
  `);
  return inserted.rows[0].id;
}

async function ensureGrade(curriculumId: number, level: number): Promise<number> {
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM grades WHERE curriculum_id = ${curriculumId} AND level = ${level}
  `);
  if (existing.rows[0]) return existing.rows[0].id;

  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO grades (curriculum_id, level, label)
    VALUES (${curriculumId}, ${level}, ${"Grade " + level})
    RETURNING id
  `);
  return inserted.rows[0].id;
}

async function ensureSubject(name: string): Promise<number> {
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM subjects WHERE name = ${name}
  `);
  if (existing.rows[0]) return existing.rows[0].id;

  const code = name.replace(/[^A-Z]/gi, "").substring(0, 3).toUpperCase();
  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO subjects (name, code, description, min_grade, max_grade, is_active)
    VALUES (${name}, ${code}, ${name + " — NSC Subject"}, 10, 12, true)
    RETURNING id
  `);
  return inserted.rows[0].id;
}

async function ensureNscPaper(
  subjectId: number,
  gradeId: number | null,
  subject: string,
  grade: number,
  year: number,
  session: string,
  paperNumber: number,
  language: string,
): Promise<number> {
  const specKey = `${subject}|${grade}|${paperNumber}`;
  const spec = PAPER_SPECS[specKey];

  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM nsc_papers
    WHERE subject_id    = ${subjectId}
      AND year          = ${year}
      AND session       = ${session}::exam_session
      AND paper_number  = ${paperNumber}
      AND language      = ${language}
  `);

  if (existing.rows[0]) {
    // Backfill marks/duration if we now know them and they're missing
    if (spec) {
      await db.execute(sql`
        UPDATE nsc_papers
        SET
          total_marks      = COALESCE(total_marks,      ${spec.totalMarks}),
          duration_minutes = COALESCE(duration_minutes, ${spec.durationMinutes}),
          updated_at       = now()
        WHERE id = ${existing.rows[0].id}
      `);
    }
    return existing.rows[0].id;
  }

  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO nsc_papers (
      subject_id, grade_id, year, session, paper_number, language,
      total_marks, duration_minutes
    )
    VALUES (
      ${subjectId}, ${gradeId}, ${year}, ${session}::exam_session,
      ${paperNumber}, ${language},
      ${spec?.totalMarks ?? null}, ${spec?.durationMinutes ?? null}
    )
    RETURNING id
  `);
  return inserted.rows[0].id;
}

async function ensureNscPaperDocument(
  nscPaperId: number,
  subjectId: number,
  gradeId: number,
  year: number,
  session: string,
  paperNumber: number,
  docType: string,
  title: string,
  fileUrl: string,
  filePath: string,
  language: string,
): Promise<void> {
  const sourceRelPath = deriveSourceRelPath({
    educationFolder: EDUCATION_FOLDER,
    filePath,
    fileUrl,
  });

  const existing = await db.execute<{ id: number; education_asset_id: number | null }>(sql`
    SELECT id, education_asset_id FROM nsc_paper_documents
    WHERE nsc_paper_id = ${nscPaperId} AND file_path = ${filePath}
  `);

  let fileSize: number | null = null;
  try { fileSize = fs.statSync(filePath).size; } catch { /* inaccessible */ }

  const ext = path.extname(filePath).toLowerCase();
  const MIME_TYPES: Record<string, string> = {
    ".pdf":  "application/pdf",
    ".docx": "application/msword",   // full OOXML type is 71 chars, exceeds varchar(60)
    ".doc":  "application/msword",
    ".zip":  "application/zip",
    ".exe":  "application/x-msdownload",
  };

  const mimeType = MIME_TYPES[ext] ?? "application/octet-stream";
  const educationAssetId =
    sourceRelPath === null
      ? null
      : await upsertEducationAsset({
          subjectId,
          gradeId,
          kind: docTypeToAssetKind(docType),
          category: docTypeToAssetCategory(docType),
          title,
          sourceRelPath,
          sourceAbsPath: filePath,
          mimeType,
          fileSize,
          language,
          year,
          session,
          paperNumber,
          isAvailable: fileSize !== null,
          metadata: {
            source: "seed-nsc-papers",
            docType,
          },
        });

  if (existing.rows[0]) {
    await db.execute(sql`
      UPDATE nsc_paper_documents
      SET
        file_url = ${fileUrl},
        file_size = ${fileSize},
        mime_type = ${mimeType},
        education_asset_id = COALESCE(${educationAssetId}, education_asset_id)
      WHERE id = ${existing.rows[0].id}
    `);
    return;
  }

  await db.execute(sql`
    INSERT INTO nsc_paper_documents
      (nsc_paper_id, doc_type, title, file_url, file_path, education_asset_id, file_size, mime_type, language)
    VALUES (
      ${nscPaperId},
      ${docType}::paper_doc_type,
      ${title},
      ${fileUrl},
      ${filePath},
      ${educationAssetId},
      ${fileSize},
      ${mimeType},
      ${language}
    )
  `);
}

async function ensureNscPaperQuestion(
  nscPaperId: number,
  question: SampleQuestion,
): Promise<void> {
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM nsc_paper_questions
    WHERE nsc_paper_id = ${nscPaperId} AND question_number = ${question.questionNumber}
  `);

  if (existing.rows[0]) {
    await db.execute(sql`
      UPDATE nsc_paper_questions
      SET question_text = ${question.questionText},
          marks         = ${question.marks},
          section_label = ${question.sectionLabel ?? null},
          memo_text     = ${question.memoText ?? null}
      WHERE id = ${existing.rows[0].id}
    `);
    return;
  }

  await db.execute(sql`
    INSERT INTO nsc_paper_questions
      (nsc_paper_id, question_number, question_text, marks, section_label, memo_text)
    VALUES (
      ${nscPaperId}, ${question.questionNumber}, ${question.questionText},
      ${question.marks}, ${question.sectionLabel ?? null}, ${question.memoText ?? null}
    )
  `);
}

// ─── Seeding modes ────────────────────────────────────────────────────────────

async function seedSamplePapers(curriculumId: number) {
  console.log("  Using built-in NSC sample dataset.");

  const gradeCache = new Map<number, number>();
  let papersCount = 0, documentsCount = 0, questionsCount = 0;

  for (const paper of SAMPLE_PAPERS) {
    const subjectId = await ensureSubject(paper.subject);

    if (!gradeCache.has(paper.grade)) {
      gradeCache.set(paper.grade, await ensureGrade(curriculumId, paper.grade));
    }
    const gradeId = gradeCache.get(paper.grade)!;

    const nscPaperId = await ensureNscPaper(
      subjectId, gradeId, paper.subject, paper.grade,
      paper.year, paper.session, paper.paperNumber, paper.language,
    );
    papersCount++;

    for (const doc of paper.documents) {
      await ensureNscPaperDocument(
        nscPaperId, subjectId, gradeId, paper.year, paper.session, paper.paperNumber,
        doc.docType, doc.title,
        doc.fileUrl, doc.filePath, doc.language ?? paper.language,
      );
      documentsCount++;
    }

    for (const q of paper.questions) {
      await ensureNscPaperQuestion(nscPaperId, q);
      questionsCount++;
    }
  }

  console.log(`\n  ✓ ${papersCount} papers, ${documentsCount} documents, ${questionsCount} questions`);
}

async function seedFromEducationFolder(curriculumId: number) {
  const subjectFolders = fs
    .readdirSync(EDUCATION_FOLDER, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => d.name);

  if (subjectFolders.length === 0) {
    console.log("  No subject folders found — falling back to sample data.");
    return seedSamplePapers(curriculumId);
  }

  console.log(`  Subjects found: ${subjectFolders.join(", ")}\n`);

  const gradeCache = new Map<number, number>();
  const stats = { papers: 0, documents: 0, skipped: 0 };

  for (const subjectName of subjectFolders) {
    console.log(`── ${subjectName}`);

    const subjectId = await ensureSubject(subjectName);
    const subjectPath = path.join(EDUCATION_FOLDER, subjectName);
    const files = walkDirectory(subjectPath, subjectName);

    console.log(`   ${files.length} document files discovered`);

    // Group files by canonical paper key
    const paperGroups = new Map<string, ParsedFile[]>();
    for (const file of files) {
      const key = `${file.year}|${file.session}|${file.paperNumber}|${file.language}|${file.grade}`;
      if (!paperGroups.has(key)) paperGroups.set(key, []);
      paperGroups.get(key)!.push(file);
    }

    console.log(`   ${paperGroups.size} unique papers\n`);

    for (const [, paperFiles] of paperGroups) {
      const sample = paperFiles[0];

      if (!gradeCache.has(sample.grade)) {
        gradeCache.set(sample.grade, await ensureGrade(curriculumId, sample.grade));
      }
      const gradeId = gradeCache.get(sample.grade)!;

      const nscPaperId = await ensureNscPaper(
        subjectId, gradeId, sample.subject, sample.grade,
        sample.year, sample.session, sample.paperNumber, sample.language,
      );
      stats.papers++;

      const educationNorm = normalizePath(EDUCATION_FOLDER);

      for (const file of paperFiles) {
        // Store URL as path relative to the Education folder, URL-encoded per segment
        const relativeUrl = file.filePath
          .replace(educationNorm, "")
          .split("/")
          .filter(Boolean)
          .map(s => encodeURIComponent(s))
          .join("/");

        const title = buildTitle(file);

        await ensureNscPaperDocument(
          nscPaperId, subjectId, gradeId, sample.year, sample.session, sample.paperNumber,
          file.docType, title,
          relativeUrl, file.filePath, file.language,
        );
        stats.documents++;

        const indicator = file.docType === "question_paper" ? "📄"
          : file.docType === "memorandum"                   ? "✅"
          : file.docType === "marking_guideline"            ? "🎯"
          : file.docType === "data_files"                   ? "📦"
          : "📎";
        console.log(`   ${indicator} [${file.year} ${file.session} P${file.paperNumber}] ${file.docType}: ${file.fileName}`);
      }
    }
  }

  console.log(`\n=== Done ===`);
  console.log(`Papers created/updated : ${stats.papers}`);
  console.log(`Documents registered   : ${stats.documents}`);
}

// ─── Entry point ─────────────────────────────────────────────────────────────

async function main() {
  console.log("NSC Papers Seeding\n");
  console.log(`Education folder: ${EDUCATION_FOLDER}\n`);

  const curriculumId = await ensureCurriculum();
  console.log(`CAPS curriculum id: ${curriculumId}\n`);

  if (!fs.existsSync(EDUCATION_FOLDER)) {
    console.log("Education folder not found — seeding built-in sample papers.\n");
    await seedSamplePapers(curriculumId);
  } else {
    await seedFromEducationFolder(curriculumId);
  }
}

main().catch(err => {
  console.error("Seeding failed:", err);
  process.exit(1);
});
