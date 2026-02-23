import { asyncHandler } from "../../core/middleware/async-handler.js";
import { parseNumber } from "../../shared/utils/parse.js";
import {
  listPapers,
  createPaper,
  getPaper,
  updatePaper,
  deletePaper,
  publishPaper,
  closePaper,
  startMarkingPaper,
  releasePaper,
  addSection,
  updateSection,
  deleteSection,
  addQuestionToSection,
  updatePaperQuestion,
  removePaperQuestion,
  assignPaper,
  listAssignments,
  removeAssignment,
  listSubmissions,
  getSubmission,
  markAnswer,
  finalizeMarking,
  getMyPapers,
  startPaper,
  getPaperResult,
} from "./papers.service.js";

// ── Admin: papers ─────────────────────────────────────────────────────────────

export const list = asyncHandler(async (req, res) => {
  const { subjectId, status, limit, offset } = req.query;
  const papers = await listPapers({
    role: req.user!.role,
    subjectId: subjectId ? Number(subjectId) : undefined,
    status: status as string | undefined,
    limit: limit ? Number(limit) : undefined,
    offset: offset ? Number(offset) : undefined,
  });
  res.json(papers);
});

export const create = asyncHandler(async (req, res) => {
  const paper = await createPaper(req.body, req.user!.id);
  res.status(201).json({ paper });
});

export const getById = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const paper = await getPaper(id);
  res.json(paper);
});

export const update = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const paper = await updatePaper(id, req.body);
  res.json(paper);
});

export const remove = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  await deletePaper(id);
  res.status(204).end();
});

export const publish = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const paper = await publishPaper(id);
  res.json(paper);
});

export const close = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const paper = await closePaper(id);
  res.json(paper);
});

export const startMarking = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const paper = await startMarkingPaper(id);
  res.json(paper);
});

export const release = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const paper = await releasePaper(id);
  res.json(paper);
});

// ── Admin: sections ───────────────────────────────────────────────────────────

export const createSection = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const section = await addSection(id, req.body);
  res.status(201).json(section);
});

export const updateSectionHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const sectionId = parseNumber(req.params.sectionId as string);
  if (!id || !sectionId) { res.status(400).json({ message: "Invalid ID" }); return; }
  const section = await updateSection(id, sectionId, req.body);
  res.json(section);
});

export const deleteSectionHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const sectionId = parseNumber(req.params.sectionId as string);
  if (!id || !sectionId) { res.status(400).json({ message: "Invalid ID" }); return; }
  await deleteSection(id, sectionId);
  res.status(204).end();
});

// ── Admin: questions ──────────────────────────────────────────────────────────

export const addQuestion = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const sectionId = parseNumber(req.params.sectionId as string);
  if (!id || !sectionId) { res.status(400).json({ message: "Invalid ID" }); return; }
  const pq = await addQuestionToSection(id, sectionId, req.body);
  res.status(201).json(pq);
});

export const patchQuestion = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const sectionId = parseNumber(req.params.sectionId as string);
  const pqId = parseNumber(req.params.pqId as string);
  if (!id || !sectionId || !pqId) { res.status(400).json({ message: "Invalid ID" }); return; }
  const pq = await updatePaperQuestion(id, sectionId, pqId, req.body);
  res.json(pq);
});

export const removeQuestion = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const sectionId = parseNumber(req.params.sectionId as string);
  const pqId = parseNumber(req.params.pqId as string);
  if (!id || !sectionId || !pqId) { res.status(400).json({ message: "Invalid ID" }); return; }
  await removePaperQuestion(id, sectionId, pqId);
  res.status(204).end();
});

// ── Admin: assignments ────────────────────────────────────────────────────────

export const assign = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const result = await assignPaper(id, req.body, req.user!.id);
  res.status(201).json(result);
});

export const getAssignments = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const assignments = await listAssignments(id);
  res.json(assignments);
});

export const deleteAssignment = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const assignmentId = parseNumber(req.params.assignmentId as string);
  if (!id || !assignmentId) { res.status(400).json({ message: "Invalid ID" }); return; }
  await removeAssignment(id, assignmentId);
  res.status(204).end();
});

// ── Admin: submissions / marking ──────────────────────────────────────────────

export const getSubmissions = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const submissions = await listSubmissions(id);
  res.json(submissions);
});

export const getSubmissionById = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const submission = await getSubmission(id, req.params.attemptId as string);
  res.json(submission);
});

export const markAnswerHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const answerId = parseNumber(req.params.answerId as string);
  if (!id || !answerId) { res.status(400).json({ message: "Invalid ID" }); return; }
  const updated = await markAnswer(
    id,
    req.params.attemptId as string,
    answerId,
    req.body,
    req.user!.id,
  );
  res.json(updated);
});

export const finalizeMarkingHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const updated = await finalizeMarking(
    id,
    req.params.attemptId as string,
    req.user!.id,
  );
  res.json(updated);
});

// ── Student-facing ─────────────────────────────────────────────────────────────

export const myPapers = asyncHandler(async (req, res) => {
  const papers = await getMyPapers(req.user!.id);
  res.json(papers);
});

export const startPaperHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const attempt = await startPaper(id, req.user!.id);
  res.status(201).json(attempt);
});

export const getPaperResultHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid paper ID" }); return; }
  const result = await getPaperResult(id, req.user!.id);
  res.json(result);
});
