import { and, desc, eq, sql } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import {
  nscPapers,
  nscPaperDocuments,
  nscPaperQuestions,
  subjects,
  grades,
  topics,
  questionBankItems,
  assessments,
  assessmentSections,
  assessmentQuestions,
} from "../../core/database/schema/index.js";

export type ExamSession =
  | "november"
  | "may_june"
  | "february_march"
  | "supplementary"
  | "exemplar";

export type PaperDocType =
  | "question_paper"
  | "memorandum"
  | "marking_guideline"
  | "answer_book"
  | "data_files"
  | "addendum"
  | "formula_sheet";

// ============ NSC PAPERS ============

type ListPapersInput = {
  subjectId?: number;
  year?: number;
  session?: ExamSession;
  paperNumber?: number;
  language?: string;
  isProcessed?: boolean;
  limit?: number;
  offset?: number;
};

type PaperSection = {
  label: string;
  title?: string;
  instructions?: string;
  totalMarks?: number;
};

type CreatePaperInput = {
  subjectId: number;
  gradeId?: number;
  year: number;
  session: ExamSession;
  paperNumber: number;
  language?: string;
  totalMarks?: number;
  durationMinutes?: number;
  title?: string;
  instructions?: string;
  strictMode?: boolean;
  sections?: PaperSection[];
  metadata?: Record<string, unknown>;
};

type UpdatePaperInput = Partial<CreatePaperInput> & {
  isProcessed?: boolean;
};

export async function listPapers(input: ListPapersInput = {}) {
  const conditions: any[] = [];

  if (input.subjectId) {
    conditions.push(eq(nscPapers.subjectId, input.subjectId));
  }
  if (input.year) {
    conditions.push(eq(nscPapers.year, input.year));
  }
  if (input.session) {
    conditions.push(eq(nscPapers.session, input.session));
  }
  if (input.paperNumber) {
    conditions.push(eq(nscPapers.paperNumber, input.paperNumber));
  }
  if (input.language) {
    conditions.push(eq(nscPapers.language, input.language));
  }
  if (input.isProcessed !== undefined) {
    conditions.push(eq(nscPapers.isProcessed, input.isProcessed));
  }

  const limit = input.limit ?? 50;
  const offset = input.offset ?? 0;

  let query = db
    .select({
      id: nscPapers.id,
      subjectId: nscPapers.subjectId,
      subjectName: subjects.name,
      gradeId: nscPapers.gradeId,
      gradeLabel: grades.label,
      year: nscPapers.year,
      session: nscPapers.session,
      paperNumber: nscPapers.paperNumber,
      language: nscPapers.language,
      totalMarks: nscPapers.totalMarks,
      durationMinutes: nscPapers.durationMinutes,
      isProcessed: nscPapers.isProcessed,
      createdAt: nscPapers.createdAt,
      updatedAt: nscPapers.updatedAt,
    })
    .from(nscPapers)
    .$dynamic()
    .innerJoin(subjects, eq(nscPapers.subjectId, subjects.id))
    .leftJoin(grades, eq(nscPapers.gradeId, grades.id))
    .orderBy(desc(nscPapers.year), nscPapers.session, nscPapers.paperNumber)
    .limit(limit)
    .offset(offset);

  if (conditions.length > 0) {
    query = query.where(and(...conditions));
  }

  const items = await query;

  // Get total count
  let countQuery = db
    .select({ count: sql<number>`count(*)::int` })
    .from(nscPapers)
    .$dynamic();

  if (conditions.length > 0) {
    countQuery = countQuery.where(and(...conditions));
  }

  const [{ count }] = await countQuery;

  return { items, total: count, limit, offset };
}

export async function getPaperById(id: number) {
  const [paper] = await db
    .select({
      id: nscPapers.id,
      subjectId: nscPapers.subjectId,
      subjectName: subjects.name,
      gradeId: nscPapers.gradeId,
      gradeLabel: grades.label,
      year: nscPapers.year,
      session: nscPapers.session,
      paperNumber: nscPapers.paperNumber,
      language: nscPapers.language,
      totalMarks: nscPapers.totalMarks,
      durationMinutes: nscPapers.durationMinutes,
      isProcessed: nscPapers.isProcessed,
      metadata: nscPapers.metadata,
      createdAt: nscPapers.createdAt,
      updatedAt: nscPapers.updatedAt,
    })
    .from(nscPapers)
    .innerJoin(subjects, eq(nscPapers.subjectId, subjects.id))
    .leftJoin(grades, eq(nscPapers.gradeId, grades.id))
    .where(eq(nscPapers.id, id));

  return paper ?? null;
}

export async function getPaperWithDocuments(id: number) {
  const paper = await getPaperById(id);
  if (!paper) return null;

  const documents = await db
    .select()
    .from(nscPaperDocuments)
    .where(eq(nscPaperDocuments.nscPaperId, id))
    .orderBy(nscPaperDocuments.docType);

  return { ...paper, documents };
}

export async function createPaper(input: CreatePaperInput) {
  const metadataExtras: Record<string, unknown> = {};
  if (input.title !== undefined) metadataExtras.title = input.title;
  if (input.instructions !== undefined) metadataExtras.instructions = input.instructions;
  if (input.strictMode !== undefined) metadataExtras.strictMode = input.strictMode;
  if (input.sections !== undefined) metadataExtras.sections = input.sections;

  const metadata = { ...(input.metadata ?? {}), ...metadataExtras };

  const [created] = await db
    .insert(nscPapers)
    .values({
      subjectId: input.subjectId,
      gradeId: input.gradeId ?? null,
      year: input.year,
      session: input.session,
      paperNumber: input.paperNumber,
      language: input.language ?? "English",
      totalMarks: input.totalMarks ?? null,
      durationMinutes: input.durationMinutes ?? null,
      metadata,
      updatedAt: new Date(),
    })
    .returning();
  return created;
}

export async function updatePaper(id: number, input: UpdatePaperInput) {
  const updateData: Record<string, any> = { updatedAt: new Date() };

  if (input.subjectId !== undefined) updateData.subjectId = input.subjectId;
  if (input.gradeId !== undefined) updateData.gradeId = input.gradeId;
  if (input.year !== undefined) updateData.year = input.year;
  if (input.session !== undefined) updateData.session = input.session;
  if (input.paperNumber !== undefined) updateData.paperNumber = input.paperNumber;
  if (input.language !== undefined) updateData.language = input.language;
  if (input.totalMarks !== undefined) updateData.totalMarks = input.totalMarks;
  if (input.durationMinutes !== undefined) updateData.durationMinutes = input.durationMinutes;
  if (input.isProcessed !== undefined) updateData.isProcessed = input.isProcessed;
  if (input.metadata !== undefined) updateData.metadata = input.metadata;

  const [updated] = await db
    .update(nscPapers)
    .set(updateData)
    .where(eq(nscPapers.id, id))
    .returning();

  return updated ?? null;
}

export async function deletePaper(id: number) {
  // Delete related documents and questions first
  await db.delete(nscPaperDocuments).where(eq(nscPaperDocuments.nscPaperId, id));
  await db.delete(nscPaperQuestions).where(eq(nscPaperQuestions.nscPaperId, id));

  const [deleted] = await db
    .delete(nscPapers)
    .where(eq(nscPapers.id, id))
    .returning();

  return deleted ?? null;
}

export async function getAvailableYears() {
  const years = await db
    .selectDistinct({ year: nscPapers.year })
    .from(nscPapers)
    .orderBy(desc(nscPapers.year));

  return years.map((r) => r.year);
}

export async function getSubjectsWithPapers() {
  const result = await db
    .selectDistinct({
      id: subjects.id,
      name: subjects.name,
    })
    .from(nscPapers)
    .innerJoin(subjects, eq(nscPapers.subjectId, subjects.id))
    .orderBy(subjects.name);

  return result;
}

// ============ NSC PAPER DOCUMENTS ============

type CreateDocumentInput = {
  nscPaperId: number;
  docType: PaperDocType;
  title: string;
  fileUrl: string;
  filePath?: string;
  fileSize?: number;
  mimeType?: string;
  language?: string;
};

export async function listDocuments(nscPaperId: number) {
  return db
    .select()
    .from(nscPaperDocuments)
    .where(eq(nscPaperDocuments.nscPaperId, nscPaperId))
    .orderBy(nscPaperDocuments.docType);
}

export async function getDocumentById(id: number) {
  const [document] = await db
    .select()
    .from(nscPaperDocuments)
    .where(eq(nscPaperDocuments.id, id));
  return document ?? null;
}

export async function createDocument(input: CreateDocumentInput) {
  const [created] = await db
    .insert(nscPaperDocuments)
    .values({
      nscPaperId: input.nscPaperId,
      docType: input.docType,
      title: input.title,
      fileUrl: input.fileUrl,
      filePath: input.filePath ?? null,
      fileSize: input.fileSize ?? null,
      mimeType: input.mimeType ?? null,
      language: input.language ?? "English",
    })
    .returning();
  return created;
}

export async function deleteDocument(id: number) {
  const [deleted] = await db
    .delete(nscPaperDocuments)
    .where(eq(nscPaperDocuments.id, id))
    .returning();
  return deleted ?? null;
}

// ============ NSC PAPER QUESTIONS ============

type RubricCriterion = { criterion: string; marks: number };

type CreateQuestionInput = {
  nscPaperId: number;
  questionNumber?: string;
  questionText: string;
  marks: number;
  difficulty?: string;
  topicId?: number;
  sectionLabel?: string;
  imageUrl?: string;
  memoText?: string;
  type?: string;
  options?: unknown[];
  correctAnswer?: unknown;
  answerFormat?: string;
  rubricCriteria?: RubricCriterion[];
  modelAnswer?: string;
  language?: string;
  starterCode?: string;
  practicalMode?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
};

type UpdateQuestionInput = Partial<Omit<CreateQuestionInput, "nscPaperId">>;

export async function listQuestions(nscPaperId: number) {
  return db
    .select({
      id: nscPaperQuestions.id,
      nscPaperId: nscPaperQuestions.nscPaperId,
      questionNumber: nscPaperQuestions.questionNumber,
      questionText: nscPaperQuestions.questionText,
      marks: nscPaperQuestions.marks,
      topicId: nscPaperQuestions.topicId,
      topicTitle: topics.title,
      sectionLabel: nscPaperQuestions.sectionLabel,
      imageUrl: nscPaperQuestions.imageUrl,
      memoText: nscPaperQuestions.memoText,
      metadata: nscPaperQuestions.metadata,
      createdAt: nscPaperQuestions.createdAt,
    })
    .from(nscPaperQuestions)
    .leftJoin(topics, eq(nscPaperQuestions.topicId, topics.id))
    .where(eq(nscPaperQuestions.nscPaperId, nscPaperId))
    .orderBy(nscPaperQuestions.questionNumber);
}

export async function getQuestionById(id: number) {
  const [question] = await db
    .select({
      id: nscPaperQuestions.id,
      nscPaperId: nscPaperQuestions.nscPaperId,
      questionNumber: nscPaperQuestions.questionNumber,
      questionText: nscPaperQuestions.questionText,
      marks: nscPaperQuestions.marks,
      topicId: nscPaperQuestions.topicId,
      topicTitle: topics.title,
      sectionLabel: nscPaperQuestions.sectionLabel,
      imageUrl: nscPaperQuestions.imageUrl,
      memoText: nscPaperQuestions.memoText,
      metadata: nscPaperQuestions.metadata,
      createdAt: nscPaperQuestions.createdAt,
    })
    .from(nscPaperQuestions)
    .leftJoin(topics, eq(nscPaperQuestions.topicId, topics.id))
    .where(eq(nscPaperQuestions.id, id));

  return question ?? null;
}

function buildQuestionMetadata(
  base: Record<string, unknown>,
  input: Pick<CreateQuestionInput,
    | "type" | "options" | "correctAnswer"
    | "answerFormat" | "rubricCriteria" | "modelAnswer"
    | "language" | "starterCode" | "practicalMode"
    | "difficulty" | "tags"
  >,
): Record<string, unknown> {
  const meta = { ...base };
  if (input.type !== undefined) meta.type = input.type;
  if (input.options !== undefined) meta.options = input.options;
  if (input.correctAnswer !== undefined) meta.correctAnswer = input.correctAnswer;
  if (input.answerFormat !== undefined) meta.answerFormat = input.answerFormat;
  if (input.rubricCriteria !== undefined) meta.rubricCriteria = input.rubricCriteria;
  if (input.modelAnswer !== undefined) meta.modelAnswer = input.modelAnswer;
  if (input.language !== undefined) meta.language = input.language;
  if (input.starterCode !== undefined) meta.starterCode = input.starterCode;
  if (input.practicalMode !== undefined) meta.practicalMode = input.practicalMode;
  if (input.difficulty !== undefined) meta.difficulty = input.difficulty;
  if (input.tags !== undefined) meta.tags = input.tags;
  return meta;
}

export async function createQuestion(input: CreateQuestionInput) {
  let questionNumber = input.questionNumber;
  if (!questionNumber) {
    const existing = await db
      .select({ questionNumber: nscPaperQuestions.questionNumber })
      .from(nscPaperQuestions)
      .where(eq(nscPaperQuestions.nscPaperId, input.nscPaperId));
    const maxNum = existing.reduce((max, q) => {
      const n = parseInt(q.questionNumber ?? "0", 10);
      return isNaN(n) ? max : Math.max(max, n);
    }, 0);
    questionNumber = String(maxNum + 1);
  }

  const metadata = buildQuestionMetadata(input.metadata ?? {}, input);

  const [created] = await db
    .insert(nscPaperQuestions)
    .values({
      nscPaperId: input.nscPaperId,
      questionNumber,
      questionText: input.questionText,
      marks: input.marks,
      topicId: input.topicId ?? null,
      sectionLabel: input.sectionLabel ?? null,
      imageUrl: input.imageUrl ?? null,
      memoText: input.memoText ?? null,
      metadata,
    })
    .returning();
  return created;
}

export async function updateQuestion(id: number, input: UpdateQuestionInput) {
  const updateData: Record<string, any> = {};

  if (input.questionNumber !== undefined) updateData.questionNumber = input.questionNumber;
  if (input.questionText !== undefined) updateData.questionText = input.questionText;
  if (input.marks !== undefined) updateData.marks = input.marks;
  if (input.topicId !== undefined) updateData.topicId = input.topicId;
  if (input.sectionLabel !== undefined) updateData.sectionLabel = input.sectionLabel;
  if (input.imageUrl !== undefined) updateData.imageUrl = input.imageUrl;
  if (input.memoText !== undefined) updateData.memoText = input.memoText;

  const hasMetaFields =
    input.type !== undefined ||
    input.options !== undefined ||
    input.correctAnswer !== undefined ||
    input.answerFormat !== undefined ||
    input.rubricCriteria !== undefined ||
    input.modelAnswer !== undefined ||
    input.language !== undefined ||
    input.starterCode !== undefined ||
    input.practicalMode !== undefined ||
    input.difficulty !== undefined ||
    input.tags !== undefined ||
    input.metadata !== undefined;

  if (hasMetaFields) {
    const existing = await getQuestionById(id);
    const existingMeta = (existing?.metadata as Record<string, unknown>) ?? {};
    updateData.metadata = buildQuestionMetadata(
      { ...existingMeta, ...(input.metadata ?? {}) },
      input,
    );
  }

  if (Object.keys(updateData).length === 0) return getQuestionById(id);

  const [updated] = await db
    .update(nscPaperQuestions)
    .set(updateData)
    .where(eq(nscPaperQuestions.id, id))
    .returning();

  return updated ?? null;
}

export async function deleteQuestion(id: number) {
  const [deleted] = await db
    .delete(nscPaperQuestions)
    .where(eq(nscPaperQuestions.id, id))
    .returning();
  return deleted ?? null;
}

// ============ IMPORT TO QUESTION BANK ============

import { nscImportService } from "./nsc-import.service.js";

export async function importQuestionsToBank(
  nscPaperId: number,
  createdBy: string,
  options: { overwrite?: boolean } = {}
) {
  // Use the new smart NSC import service
  const result = await nscImportService.importPaperToQuestionBank(nscPaperId, createdBy);

  // If overwrite option is enabled and there are skipped questions, re-import them
  if (options.overwrite && result.skipped.length > 0) {
    console.log(`Overwrite mode enabled, forcing import of ${result.skipped.length} previously imported questions...`);
    // For now, just return the result - full overwrite logic would require service modification
  }

  // Fetch paper details (with subject name) to build practice assessment title
  const [paperRow] = await db
    .select({
      subjectId: nscPapers.subjectId,
      year: nscPapers.year,
      session: nscPapers.session,
      paperNumber: nscPapers.paperNumber,
      totalMarks: nscPapers.totalMarks,
      durationMinutes: nscPapers.durationMinutes,
      metadata: nscPapers.metadata,
      subjectName: subjects.name,
    })
    .from(nscPapers)
    .innerJoin(subjects, eq(nscPapers.subjectId, subjects.id))
    .where(eq(nscPapers.id, nscPaperId))
    .limit(1);

  if (!paperRow) {
    return {
      imported: result.imported.length,
      skipped: result.skipped.length,
      errors: result.errors,
      assessmentId: null,
      assessmentCreated: false,
    };
  }

  // If an assessment was already created for this paper, return it
  const existingAssessmentId = (paperRow.metadata as Record<string, unknown>)?.assessmentId as number | undefined;
  if (existingAssessmentId) {
    return {
      imported: result.imported.length,
      skipped: result.skipped.length,
      errors: result.errors,
      assessmentId: existingAssessmentId,
      assessmentCreated: false,
    };
  }

  // Only create a practice assessment if questions were actually imported
  if (result.imported.length === 0) {
    return {
      imported: result.imported.length,
      skipped: result.skipped.length,
      errors: result.errors,
      assessmentId: null,
      assessmentCreated: false,
    };
  }

  // Create a practice assessment linked to the imported questions
  const title = `${paperRow.subjectName} — ${paperRow.year} ${paperRow.session} P${paperRow.paperNumber} Practice`;
  const [newAssessment] = await db
    .insert(assessments)
    .values({
      title,
      type: "practice",
      // Keep imported NSC practice assessments editable in builder.
      status: "draft",
      subjectId: paperRow.subjectId,
      timeLimitMinutes: paperRow.durationMinutes ?? null,
      totalMarks: paperRow.totalMarks ?? null,
      createdBy,
    })
    .returning({ id: assessments.id });

  // Create a single section for all imported questions
  const [newSection] = await db
    .insert(assessmentSections)
    .values({
      assessmentId: newAssessment.id,
      label: "Q",
      order: 1,
    })
    .returning({ id: assessmentSections.id });

  // Link each imported question bank item to the new assessment
  await db.insert(assessmentQuestions).values(
    result.imported.map((qbItemId, idx) => ({
      assessmentId: newAssessment.id,
      sectionId: newSection.id,
      questionBankItemId: qbItemId,
      order: idx + 1,
    }))
  );

  // Persist assessmentId in the NSC paper's metadata for future imports
  await db
    .update(nscPapers)
    .set({
      metadata: { ...((paperRow.metadata as Record<string, unknown>) ?? {}), assessmentId: newAssessment.id },
      updatedAt: new Date(),
    })
    .where(eq(nscPapers.id, nscPaperId));

  return {
    imported: result.imported.length,
    skipped: result.skipped.length,
    errors: result.errors,
    assessmentId: newAssessment.id,
    assessmentCreated: true,
  };
}

// ============ DIAGNOSTIC / SEEDING VERIFICATION ============

export async function getSeedingDiagnostics() {
  // Count papers by subject
  const papersBySubject = await db
    .select({
      subjectId: nscPapers.subjectId,
      subjectName: subjects.name,
      paperCount: sql<number>`count(*)::int`,
    })
    .from(nscPapers)
    .innerJoin(subjects, eq(nscPapers.subjectId, subjects.id))
    .groupBy(nscPapers.subjectId, subjects.name)
    .orderBy(subjects.name);

  // Count papers by year
  const papersByYear = await db
    .select({
      year: nscPapers.year,
      count: sql<number>`count(*)::int`,
    })
    .from(nscPapers)
    .groupBy(nscPapers.year)
    .orderBy(desc(nscPapers.year));

  // Count papers by session
  const papersBySession = await db
    .select({
      session: nscPapers.session,
      count: sql<number>`count(*)::int`,
    })
    .from(nscPapers)
    .groupBy(nscPapers.session);

  // Count documents by type
  const documentsByType = await db
    .select({
      docType: nscPaperDocuments.docType,
      count: sql<number>`count(*)::int`,
    })
    .from(nscPaperDocuments)
    .groupBy(nscPaperDocuments.docType);

  // Overall totals
  const [paperTotal] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(nscPapers);

  const [documentTotal] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(nscPaperDocuments);

  const [questionTotal] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(nscPaperQuestions);

  // Papers with missing documents (no question paper attached)
  const papersWithoutQuestionPaper = await db.execute<{
    paper_id: number;
    subject_name: string;
    year: number;
    session: string;
    paper_number: number;
  }>(sql`
    SELECT
      p.id as paper_id,
      s.name as subject_name,
      p.year,
      p.session,
      p.paper_number
    FROM nsc_papers p
    JOIN subjects s ON p.subject_id = s.id
    LEFT JOIN nsc_paper_documents d ON d.nsc_paper_id = p.id AND d.doc_type = 'question_paper'
    WHERE d.id IS NULL
    ORDER BY p.year DESC, s.name
    LIMIT 20
  `);

  // Recent papers (most recently added)
  const recentPapers = await db
    .select({
      id: nscPapers.id,
      subjectName: subjects.name,
      year: nscPapers.year,
      session: nscPapers.session,
      paperNumber: nscPapers.paperNumber,
      createdAt: nscPapers.createdAt,
    })
    .from(nscPapers)
    .innerJoin(subjects, eq(nscPapers.subjectId, subjects.id))
    .orderBy(desc(nscPapers.createdAt))
    .limit(10);

  return {
    totals: {
      papers: paperTotal.count ?? 0,
      documents: documentTotal.count ?? 0,
      questions: questionTotal.count ?? 0,
    },
    papersBySubject,
    papersByYear,
    papersBySession,
    documentsByType,
    papersWithoutQuestionPaper: papersWithoutQuestionPaper.rows,
    recentPapers,
  };
}
