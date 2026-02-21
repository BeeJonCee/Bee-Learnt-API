import "dotenv/config";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

/**
 * Subject Resources Seeding Script
 *
 * Seeds non-NSC files from the Education folder:
 * - Textbooks (Learner's Books)
 * - Teacher's Guides
 * - PAT Documents
 * - CAPS Documents
 * - Learner Data Files
 * - Study/Revision Guides
 * - Workbooks
 * - Tutoring Guides
 *
 * Also populates subjects.caps_document_url for Information Technology.
 */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EDUCATION_FOLDER = path.join(__dirname, "../../Education");

// ============ TYPE DEFINITIONS ============

interface ResourceEntry {
  relativePath: string;
  title: string;
  type:
    | "textbook"
    | "teacher_guide"
    | "practical_guide"
    | "pat_document"
    | "caps_document"
    | "learner_data"
    | "revision_guide"
    | "workbook"
    | "tutoring_guide";
  subject: string;
  grade: number | null;
  description?: string;
}

// ============ RESOURCE CATALOG ============

const RESOURCE_CATALOG: ResourceEntry[] = [
  // ── IT Grade 10 ──
  {
    relativePath: "Information Technology/Grade 10/Gr10_IT-Theory-LB-Print-16Jan2020.pdf",
    title: "IT Theory Learner's Book - Grade 10",
    type: "textbook",
    subject: "Information Technology",
    grade: 10,
    description: "Official CAPS-aligned IT Theory textbook for Grade 10",
  },
  {
    relativePath: "Information Technology/Grade 10/Gr10_IT-Practical-LB-Print.pdf",
    title: "IT Practical Learner's Book - Grade 10",
    type: "practical_guide",
    subject: "Information Technology",
    grade: 10,
    description: "Official CAPS-aligned IT Practical textbook for Grade 10",
  },
  {
    relativePath: "Information Technology/Grade 10/IT Grade 10 Teacher's Guide v2.pdf",
    title: "IT Teacher's Guide - Grade 10 (v2)",
    type: "teacher_guide",
    subject: "Information Technology",
    grade: 10,
    description: "Teacher's guide for Information Technology Grade 10",
  },
  {
    relativePath: "Information Technology/Grade 10/IT PAT Grade 10 2015 Final.docx",
    title: "IT PAT - Grade 10 (2015)",
    type: "pat_document",
    subject: "Information Technology",
    grade: 10,
    description: "Practical Assessment Task for IT Grade 10 (2015)",
  },
  {
    relativePath: "Information Technology/Grade 10/IT_10_Learner_Data.zip",
    title: "IT Learner Data Files - Grade 10",
    type: "learner_data",
    subject: "Information Technology",
    grade: 10,
    description: "Database and programming data files for Grade 10 learners",
  },

  // ── IT Grade 11 ──
  {
    relativePath: "Information Technology/Grade 11/Gr11_IT-Theory-LB-PRINT.pdf",
    title: "IT Theory Learner's Book - Grade 11",
    type: "textbook",
    subject: "Information Technology",
    grade: 11,
    description: "Official CAPS-aligned IT Theory textbook for Grade 11",
  },
  {
    relativePath: "Information Technology/Grade 11/Gr11_IT-Practical-LB-HiRes.pdf",
    title: "IT Practical Learner's Book - Grade 11",
    type: "practical_guide",
    subject: "Information Technology",
    grade: 11,
    description: "Official CAPS-aligned IT Practical textbook for Grade 11",
  },
  {
    relativePath: "Information Technology/Grade 11/IT Grade 11 Teacher's Guide.pdf",
    title: "IT Teacher's Guide - Grade 11",
    type: "teacher_guide",
    subject: "Information Technology",
    grade: 11,
    description: "Teacher's guide for Information Technology Grade 11",
  },
  {
    relativePath: "Information Technology/Grade 11/IT_11_Data_Files_Learners.zip",
    title: "IT Learner Data Files - Grade 11",
    type: "learner_data",
    subject: "Information Technology",
    grade: 11,
    description: "Database and programming data files for Grade 11 learners",
  },

  // ── IT Grade 12 ──
  {
    relativePath: "Information Technology/Grade 12/Gr12_IT-Theory-LB-PRINT.pdf",
    title: "IT Theory Learner's Book - Grade 12",
    type: "textbook",
    subject: "Information Technology",
    grade: 12,
    description: "Official CAPS-aligned IT Theory textbook for Grade 12",
  },
  {
    relativePath: "Information Technology/Grade 12/Gr12_IT-Practical-LB\u2013HiRes.pdf",
    title: "IT Practical Learner's Book - Grade 12",
    type: "practical_guide",
    subject: "Information Technology",
    grade: 12,
    description: "Official CAPS-aligned IT Practical textbook for Grade 12",
  },
  {
    relativePath: "Information Technology/Grade 12/IT Grade 12 Teacher's Guide.pdf",
    title: "IT Teacher's Guide - Grade 12",
    type: "teacher_guide",
    subject: "Information Technology",
    grade: 12,
    description: "Teacher's guide for Information Technology Grade 12",
  },
  {
    relativePath: "Information Technology/Grade 12/IT_12_Data_Files_Learners.zip",
    title: "IT Learner Data Files - Grade 12",
    type: "learner_data",
    subject: "Information Technology",
    grade: 12,
    description: "Database and programming data files for Grade 12 learners",
  },

  // ── IT CAPS Document ──
  {
    relativePath: "Information Technology/IT CAPS 2024 -Section 3.pdf",
    title: "IT CAPS Document 2024 - Section 3",
    type: "caps_document",
    subject: "Information Technology",
    grade: null,
    description: "Curriculum and Assessment Policy Statement for Information Technology (Section 3, 2024)",
  },

  // ── IT PAT Grade 12 ──
  {
    relativePath: "Information Technology/979405850-Information-Technology-PAT-GR-12-2026-Eng-260105-204635.pdf",
    title: "IT PAT - Grade 12 (2026)",
    type: "pat_document",
    subject: "Information Technology",
    grade: 12,
    description: "Practical Assessment Task for IT Grade 12 (2026)",
  },

  // ── IT Grade 12 Study/Revision Guides (BeeLearnt) ──
  {
    relativePath: "Information Technology/Grade 12/past papers/2025/Grade12_IT_Full_Revision_Guide_40plus_Bee_Learnt.pdf",
    title: "IT Full Revision Guide - Grade 12 (BeeLearnt)",
    type: "revision_guide",
    subject: "Information Technology",
    grade: 12,
    description: "Comprehensive IT revision guide for Grade 12 (40+ pages)",
  },
  {
    relativePath: "Information Technology/Grade 12/past papers/2025/Grade12_IT_Term1_Study_Guide_Bee_Learnt_updated_v5.docx",
    title: "IT Term 1 Study Guide - Grade 12 (BeeLearnt v5)",
    type: "revision_guide",
    subject: "Information Technology",
    grade: 12,
    description: "Term 1 study guide for IT Grade 12 (latest version)",
  },

  // ── IT Grade 12 Workbook (BeeLearnt) ──
  {
    relativePath: "Information Technology/Grade 12/past papers/2025/Grade12_IT_Term1_Workbook_20plus_Pages_Bee_Learnt_updated_v5.docx",
    title: "IT Term 1 Workbook - Grade 12 (BeeLearnt v5)",
    type: "workbook",
    subject: "Information Technology",
    grade: 12,
    description: "Term 1 workbook for IT Grade 12 (20+ pages, latest version)",
  },

  // ── IT Grade 12 Tutoring Guide (BeeLearnt) ──
  {
    relativePath: "Information Technology/Grade 12/past papers/2025/Grade12_IT_Tutoring_Guide_Term1.pdf",
    title: "IT Tutoring Guide - Grade 12 Term 1 (BeeLearnt)",
    type: "tutoring_guide",
    subject: "Information Technology",
    grade: 12,
    description: "Tutoring guide for IT Grade 12 Term 1",
  },
];

// ============ MIME TYPE HELPERS ============

const MIME_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".doc": "application/msword",
  ".zip": "application/zip",
  ".exe": "application/x-msdownload",
};

function getMimeType(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  return MIME_TYPES[ext] || "application/octet-stream";
}

// ============ DATABASE HELPERS ============

async function ensureCurriculum(): Promise<number> {
  const existing = await db.execute<{ id: number }>(sql`
    SELECT id FROM curricula WHERE name = 'CAPS' AND country = 'South Africa'
  `);

  if (existing.rows[0]) {
    return existing.rows[0].id;
  }

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

  const code = name.substring(0, 3).toUpperCase();
  const inserted = await db.execute<{ id: number }>(sql`
    INSERT INTO subjects (name, code, description, is_active)
    VALUES (${name}, ${code}, ${`${name} - Subject`}, true)
    RETURNING id
  `);

  return inserted.rows[0].id;
}

// ============ MAIN SEEDING FUNCTION ============

async function seedSubjectResources() {
  console.log("Starting Subject Resources seeding...\n");
  console.log(`Education folder: ${EDUCATION_FOLDER}`);

  if (!fs.existsSync(EDUCATION_FOLDER)) {
    console.error("Education folder not found!");
    process.exit(1);
  }

  const curriculumId = await ensureCurriculum();
  console.log(`CAPS Curriculum ID: ${curriculumId}`);

  const gradeCache = new Map<number, number>();
  let capsResourceId: number | null = null;
  let itSubjectId: number | null = null;

  const stats = {
    created: 0,
    skipped: 0,
    missing: 0,
  };

  for (const entry of RESOURCE_CATALOG) {
    const absolutePath = path.join(EDUCATION_FOLDER, entry.relativePath);

    // Check if file exists
    if (!fs.existsSync(absolutePath)) {
      console.log(`  MISSING: ${entry.relativePath}`);
      stats.missing++;
      continue;
    }

    // Ensure subject
    const subjectId = await ensureSubject(entry.subject);
    if (entry.subject === "Information Technology") {
      itSubjectId = subjectId;
    }

    // Ensure grade if applicable
    let gradeId: number | null = null;
    if (entry.grade) {
      if (gradeCache.has(entry.grade)) {
        gradeId = gradeCache.get(entry.grade)!;
      } else {
        gradeId = await ensureGrade(curriculumId, entry.grade);
        gradeCache.set(entry.grade, gradeId);
      }
    }

    // Get file size
    let fileSize: number | null = null;
    try {
      const stat = fs.statSync(absolutePath);
      fileSize = stat.size;
    } catch {
      // Ignore
    }

    const mimeType = getMimeType(absolutePath);
    const fileUrl = entry.relativePath
      .split("/")
      .map(segment => encodeURIComponent(segment))
      .join("/");
    const filePath = absolutePath.replace(/\\/g, "/");

    // Check if resource already exists (by file_path)
    const existing = await db.execute<{ id: number }>(sql`
      SELECT id FROM subject_resources WHERE file_path = ${filePath}
    `);

    if (existing.rows[0]) {
      console.log(`  EXISTS: ${entry.title} (id: ${existing.rows[0].id})`);
      stats.skipped++;

      // Track CAPS resource ID
      if (entry.type === "caps_document" && entry.subject === "Information Technology") {
        capsResourceId = existing.rows[0].id;
      }
      continue;
    }

    // Insert resource
    const inserted = await db.execute<{ id: number }>(sql`
      INSERT INTO subject_resources (subject_id, grade_id, title, type, file_url, file_path, file_size, mime_type, language, description)
      VALUES (
        ${subjectId},
        ${gradeId},
        ${entry.title},
        ${entry.type}::subject_resource_type,
        ${fileUrl},
        ${filePath},
        ${fileSize},
        ${mimeType},
        'English',
        ${entry.description || null}
      )
      RETURNING id
    `);

    console.log(`  + ${entry.type}: ${entry.title} (id: ${inserted.rows[0].id})`);
    stats.created++;

    // Track CAPS resource ID
    if (entry.type === "caps_document" && entry.subject === "Information Technology") {
      capsResourceId = inserted.rows[0].id;
    }
  }

  // ── Populate capsDocumentUrl on subjects table ──
  if (capsResourceId && itSubjectId) {
    const capsUrl = `/api/education/resources/${capsResourceId}/download`;
    await db.execute(sql`
      UPDATE subjects SET caps_document_url = ${capsUrl} WHERE id = ${itSubjectId}
    `);
    console.log(`\nUpdated IT subject capsDocumentUrl → ${capsUrl}`);
  }

  console.log("\n=== Subject Resources Seeding Complete ===");
  console.log(`Created: ${stats.created}`);
  console.log(`Skipped (already exist): ${stats.skipped}`);
  console.log(`Missing files: ${stats.missing}`);
}

// ============ RUN ============

seedSubjectResources().catch((error) => {
  console.error("Seeding failed:", error);
  process.exit(1);
});
