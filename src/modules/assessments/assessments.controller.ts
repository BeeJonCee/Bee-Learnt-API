import { asyncHandler } from "../../core/middleware/async-handler.js";
import { parseNumber } from "../../shared/utils/parse.js";
import {
  listAssessments,
  getAssessmentDetail,
  getAssessmentQuestionOptionsDebug,
  createAssessment,
  publishAssessment,
  startAssessmentAttempt,
} from "./assessments.service.js";
import type { AssessmentStatus, AssessmentType } from "./assessments.service.js";

// GET /api/assessments
export const list = asyncHandler(async (req, res) => {
  const { type, subjectId, status, gradeId, moduleId, limit, offset } =
    req.query;

  const result = await listAssessments({
    role: req.user!.role,
    type: type as AssessmentType | undefined,
    subjectId: subjectId ? Number(subjectId) : undefined,
    status: status as AssessmentStatus | undefined,
    grade: gradeId ? Number(gradeId) : undefined,
    moduleId: moduleId ? Number(moduleId) : undefined,
    limit: limit ? Number(limit) : undefined,
    offset: offset ? Number(offset) : undefined,
  });

  res.json(result);
});

// GET /api/assessments/:id
export const getById = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }

  const detail = await getAssessmentDetail(id);
  if (!detail) {
    res.status(404).json({ message: "Assessment not found" });
    return;
  }

  res.json(detail);
});

// GET /api/assessments/questions/:assessmentQuestionId/options-debug
export const debugQuestionOptions = asyncHandler(async (req, res) => {
  const assessmentQuestionId = parseNumber(
    req.params.assessmentQuestionId as string
  );
  if (!assessmentQuestionId) {
    res.status(400).json({ message: "Invalid assessment question ID" });
    return;
  }

  const payload = await getAssessmentQuestionOptionsDebug(assessmentQuestionId);
  if (!payload) {
    res.status(404).json({ message: "Assessment question not found" });
    return;
  }

  res.json(payload);
});

// POST /api/assessments
export const create = asyncHandler(async (req, res) => {
  const created = await createAssessment(req.body, req.user!.id);
  res.status(201).json(created);
});

// POST /api/assessments/:id/publish
export const publish = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }

  const updated = await publishAssessment(id);
  if (!updated) {
    res.status(404).json({ message: "Assessment not found" });
    return;
  }

  res.json(updated);
});

// POST /api/assessments/:id/start
export const start = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }

  const result = await startAssessmentAttempt(id, req.user!.id, req.user!.role);
  res.json(result);
});
