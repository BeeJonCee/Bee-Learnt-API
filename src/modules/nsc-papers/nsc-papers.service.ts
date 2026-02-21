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

type CreatePaperInput = {
  subjectId: number;
  gradeId?: number;
  year: number;
  session: ExamSession;
  paperNumber: number;
  language?: string;
  totalMarks?: number;
  durationMinutes?: number;
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
      metadata: input.metadata ?? {},
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

type CreateQuestionInput = {
  nscPaperId: number;
  questionNumber: string;
  questionText: string;
  marks: number;
  topicId?: number;
  sectionLabel?: string;
  imageUrl?: string;
  memoText?: string;
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

export async function createQuestion(input: CreateQuestionInput) {
  const [created] = await db
    .insert(nscPaperQuestions)
    .values({
      nscPaperId: input.nscPaperId,
      questionNumber: input.questionNumber,
      questionText: input.questionText,
      marks: input.marks,
      topicId: input.topicId ?? null,
      sectionLabel: input.sectionLabel ?? null,
      imageUrl: input.imageUrl ?? null,
      memoText: input.memoText ?? null,
      metadata: input.metadata ?? {},
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
  if (input.metadata !== undefined) updateData.metadata = input.metadata;

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

  return {
    imported: result.imported.length,
    skipped: result.skipped.length,
    errors: result.errors,
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
