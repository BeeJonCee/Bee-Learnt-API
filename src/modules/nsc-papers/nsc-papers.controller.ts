import { asyncHandler } from "../../core/middleware/async-handler.js";
import { parseNumber } from "../../shared/utils/parse.js";
import {
  listPapers,
  getPaperById,
  getPaperWithDocuments,
  createPaper,
  updatePaper,
  deletePaper,
  getAvailableYears,
  getSubjectsWithPapers,
  listDocuments,
  getDocumentById,
  createDocument,
  deleteDocument,
  listQuestions,
  getQuestionById,
  createQuestion,
  updateQuestion,
  deleteQuestion,
  importQuestionsToBank,
  getSeedingDiagnostics,
} from "./nsc-papers.service.js";

// ============ PAPERS ============

export const listPapersHandler = asyncHandler(async (req, res) => {
  // req.query is already coerced by validateQuery(nscPaperListQuerySchema)
  const q = req.query as {
    subjectId?: number;
    year?: number;
    session?: string;
    paperNumber?: number;
    language?: string;
    isProcessed?: boolean;
    limit?: number;
    offset?: number;
  };

  const result = await listPapers({
    subjectId: q.subjectId,
    year: q.year,
    session: q.session as any,
    paperNumber: q.paperNumber,
    language: q.language,
    isProcessed: q.isProcessed,
    limit: q.limit,
    offset: q.offset,
  });

  // Keep `papers` for frontend compatibility while exposing canonical `items`.
  res.json({
    ...result,
    papers: result.items,
  });
});

export const getPaperHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid paper ID" });
    return;
  }

  const paper = await getPaperWithDocuments(id);
  if (!paper) {
    res.status(404).json({ message: "Paper not found" });
    return;
  }

  res.json(paper);
});

export const createPaperHandler = asyncHandler(async (req, res) => {
  const created = await createPaper(req.body);
  res.status(201).json(created);
});

export const updatePaperHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid paper ID" });
    return;
  }

  const existing = await getPaperById(id);
  if (!existing) {
    res.status(404).json({ message: "Paper not found" });
    return;
  }

  const updated = await updatePaper(id, req.body);
  res.json(updated);
});

export const deletePaperHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid paper ID" });
    return;
  }

  const existing = await getPaperById(id);
  if (!existing) {
    res.status(404).json({ message: "Paper not found" });
    return;
  }

  await deletePaper(id);
  res.json({ message: "Paper deleted" });
});

export const getYearsHandler = asyncHandler(async (_req, res) => {
  const years = await getAvailableYears();
  res.json(years);
});

export const getSubjectsHandler = asyncHandler(async (_req, res) => {
  const subjects = await getSubjectsWithPapers();
  res.json(subjects);
});

// ============ DOCUMENTS ============

export const listDocumentsHandler = asyncHandler(async (req, res) => {
  const paperId = parseNumber(req.params.id as string);
  if (!paperId) {
    res.status(400).json({ message: "Invalid paper ID" });
    return;
  }

  const documents = await listDocuments(paperId);
  res.json(documents);
});

export const createDocumentHandler = asyncHandler(async (req, res) => {
  const paperId = parseNumber(req.params.id as string);
  if (!paperId) {
    res.status(400).json({ message: "Invalid paper ID" });
    return;
  }

  const paper = await getPaperById(paperId);
  if (!paper) {
    res.status(404).json({ message: "Paper not found" });
    return;
  }

  const { title, fileUrl, docType, language, mimeType, fileSize } = req.body as {
    title: string;
    fileUrl: string;
    docType: string;
    language?: string;
    mimeType?: string;
    fileSize?: number;
  };
  const created = await createDocument({
    nscPaperId: paperId,
    title,
    fileUrl,
    docType: docType as any,
    language,
    mimeType,
    fileSize,
  });
  res.status(201).json(created);
});

export const deleteDocumentHandler = asyncHandler(async (req, res) => {
  const docId = parseNumber(req.params.docId as string);
  if (!docId) {
    res.status(400).json({ message: "Invalid document ID" });
    return;
  }

  const existing = await getDocumentById(docId);
  if (!existing) {
    res.status(404).json({ message: "Document not found" });
    return;
  }

  await deleteDocument(docId);
  res.json({ message: "Document deleted" });
});

// ============ QUESTIONS ============

export const listQuestionsHandler = asyncHandler(async (req, res) => {
  const paperId = parseNumber(req.params.id as string);
  if (!paperId) {
    res.status(400).json({ message: "Invalid paper ID" });
    return;
  }

  const questions = await listQuestions(paperId);
  res.json(questions);
});

export const createQuestionHandler = asyncHandler(async (req, res) => {
  const paperId = parseNumber(req.params.id as string);
  if (!paperId) {
    res.status(400).json({ message: "Invalid paper ID" });
    return;
  }

  const paper = await getPaperById(paperId);
  if (!paper) {
    res.status(404).json({ message: "Paper not found" });
    return;
  }

  const created = await createQuestion({ ...req.body, nscPaperId: paperId });
  res.status(201).json(created);
});

export const updateQuestionHandler = asyncHandler(async (req, res) => {
  const questionId = parseNumber(req.params.questionId as string);
  if (!questionId) {
    res.status(400).json({ message: "Invalid question ID" });
    return;
  }

  const existing = await getQuestionById(questionId);
  if (!existing) {
    res.status(404).json({ message: "Question not found" });
    return;
  }

  const updated = await updateQuestion(questionId, req.body);
  res.json(updated);
});

export const deleteQuestionHandler = asyncHandler(async (req, res) => {
  const questionId = parseNumber(req.params.questionId as string);
  if (!questionId) {
    res.status(400).json({ message: "Invalid question ID" });
    return;
  }

  const existing = await getQuestionById(questionId);
  if (!existing) {
    res.status(404).json({ message: "Question not found" });
    return;
  }

  await deleteQuestion(questionId);
  res.json({ message: "Question deleted" });
});

// ============ IMPORT TO BANK ============

export const importToBankHandler = asyncHandler(async (req, res) => {
  const paperId = parseNumber(req.params.id as string);
  if (!paperId) {
    res.status(400).json({ message: "Invalid paper ID" });
    return;
  }

  const paper = await getPaperById(paperId);
  if (!paper) {
    res.status(404).json({ message: "Paper not found" });
    return;
  }

  const userId = req.user!.id;
  const overwrite = Boolean(req.body?.overwrite);

  const result = await importQuestionsToBank(paperId, userId, { overwrite });
  res.json({
    message: `Imported ${result.imported} questions, skipped ${result.skipped}`,
    ...result,
  });
});

// ============ DIAGNOSTICS ============

export const getDiagnosticsHandler = asyncHandler(async (_req, res) => {
  const diagnostics = await getSeedingDiagnostics();
  res.json(diagnostics);
});
