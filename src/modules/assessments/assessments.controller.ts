import { asyncHandler } from "../../core/middleware/async-handler.js";
import { parseNumber } from "../../shared/utils/parse.js";
import {
  listAssessments,
  listMyAssignedAssessments,
  getAssessmentDetail,
  getAssessmentQuestionOptionsDebug,
  createAssessment,
  startAssessmentAttempt,
  createPaper,
  getPaper as getAssessmentWorkflowDetail,
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
  updateAssignment,
  listSubmissions,
  getSubmission,
  markAnswer,
  finalizeMarking,
  getPaperResult,
  getLatestReleasedAttemptForUser,
} from "./assessments.service.js";
import type { AssessmentStatus, AssessmentType } from "./assessments.service.js";

// GET /api/assessments
export const list = asyncHandler(async (req, res) => {
  if (req.user!.role === "STUDENT") {
    const rows = await listMyAssignedAssessments(req.user!.id);
    res.json(rows);
    return;
  }

  const { type, subjectId, status, grade, gradeId, moduleId, limit, offset, page } =
    req.query;

  const parsedLimit = limit ? Number(limit) : 20;
  const parsedPage = page ? Number(page) : 1;
  const parsedOffset =
    offset !== undefined
      ? Number(offset)
      : Math.max(0, (parsedPage - 1) * parsedLimit);

  const result = await listAssessments({
    role: req.user!.role,
    type: type as AssessmentType | undefined,
    subjectId: subjectId ? Number(subjectId) : undefined,
    status: status as AssessmentStatus | undefined,
    grade: grade ? Number(grade) : gradeId ? Number(gradeId) : undefined,
    moduleId: moduleId ? Number(moduleId) : undefined,
    limit: parsedLimit,
    offset: parsedOffset,
  });

  res.json(result);
});

// GET /api/assessments/my-assessments
export const listMine = asyncHandler(async (req, res) => {
  const rows = await listMyAssignedAssessments(req.user!.id);
  res.json(rows);
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

// GET /api/assessments/:id/workflow
export const getWorkflow = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }

  const payload = await getAssessmentWorkflowDetail(id);
  res.json(payload);
});

// POST /api/assessments
export const create = asyncHandler(async (req, res) => {
  const payload = req.body ?? {};
  const toOptionalNumber = (value: unknown): number | undefined => {
    if (value === undefined || value === null || value === "") return undefined;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  };
  const requestedType = typeof payload.type === "string" ? payload.type : null;
  const isPaperWorkflowPayload =
    requestedType === null ||
    payload.paperType !== undefined ||
    payload.strictMode !== undefined ||
    payload.isManualPaper === true;

  if (isPaperWorkflowPayload) {
    const title = String(payload.title ?? "").trim();
    const subjectId = Number(payload.subjectId);
    if (!title || !Number.isFinite(subjectId) || subjectId <= 0) {
      res.status(400).json({
        message: "title and subjectId are required for assessment creation",
      });
      return;
    }

    const paper = await createPaper(
      {
        title,
        subjectId,
        grade: toOptionalNumber(payload.grade ?? payload.gradeId),
        totalMarks: toOptionalNumber(payload.totalMarks),
        timeLimitMinutes: toOptionalNumber(payload.timeLimitMinutes),
        instructions:
          typeof payload.instructions === "string"
            ? payload.instructions
            : undefined,
        strictMode:
          typeof payload.strictMode === "boolean"
            ? payload.strictMode
            : undefined,
        paperType:
          typeof payload.paperType === "string"
            ? payload.paperType
            : undefined,
      },
      req.user!.id,
    );
    res.status(201).json({ paper, assessment: paper });
    return;
  }

  const created = await createAssessment(
    {
      ...payload,
      grade: toOptionalNumber(payload.grade ?? payload.gradeId),
    },
    req.user!.id,
  );
  res.status(201).json({ assessment: created });
});

// POST /api/assessments/:id/publish
export const publish = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }

  const updated = await publishPaper(id);
  res.json(updated);
});

// POST /api/assessments/:id/close
export const close = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }
  const updated = await closePaper(id);
  res.json(updated);
});

// POST /api/assessments/:id/start-marking
export const startMarking = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }
  const updated = await startMarkingPaper(id);
  res.json(updated);
});

// POST /api/assessments/:id/release
export const release = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }
  const updated = await releasePaper(id);
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

// POST /api/assessments/:id/sections
export const createSection = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }
  const section = await addSection(id, req.body);
  res.status(201).json(section);
});

// PUT /api/assessments/:id/sections/:sectionId
export const updateSectionHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const sectionId = parseNumber(req.params.sectionId as string);
  if (!id || !sectionId) {
    res.status(400).json({ message: "Invalid ID" });
    return;
  }
  const section = await updateSection(id, sectionId, req.body);
  res.json(section);
});

// DELETE /api/assessments/:id/sections/:sectionId
export const deleteSectionHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const sectionId = parseNumber(req.params.sectionId as string);
  if (!id || !sectionId) {
    res.status(400).json({ message: "Invalid ID" });
    return;
  }
  await deleteSection(id, sectionId);
  res.status(204).end();
});

// POST /api/assessments/:id/sections/:sectionId/questions
export const addQuestion = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const sectionId = parseNumber(req.params.sectionId as string);
  if (!id || !sectionId) {
    res.status(400).json({ message: "Invalid ID" });
    return;
  }
  const row = await addQuestionToSection(id, sectionId, req.body);
  res.status(201).json(row);
});

// PATCH /api/assessments/:id/sections/:sectionId/questions/:pqId
export const patchQuestion = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const sectionId = parseNumber(req.params.sectionId as string);
  const pqId = parseNumber(req.params.pqId as string);
  if (!id || !sectionId || !pqId) {
    res.status(400).json({ message: "Invalid ID" });
    return;
  }
  const row = await updatePaperQuestion(id, sectionId, pqId, req.body);
  res.json(row);
});

// DELETE /api/assessments/:id/sections/:sectionId/questions/:pqId
export const removeQuestion = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const sectionId = parseNumber(req.params.sectionId as string);
  const pqId = parseNumber(req.params.pqId as string);
  if (!id || !sectionId || !pqId) {
    res.status(400).json({ message: "Invalid ID" });
    return;
  }
  await removePaperQuestion(id, sectionId, pqId);
  res.status(204).end();
});

// POST /api/assessments/:id/assignments
export const assign = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }
  const result = await assignPaper(id, req.body, req.user!.id);
  res.status(201).json(result);
});

// GET /api/assessments/:id/assignments
export const getAssignments = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }
  const rows = await listAssignments(id);
  res.json(rows);
});

// DELETE /api/assessments/:id/assignments/:assignmentId
export const deleteAssignment = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const assignmentId = parseNumber(req.params.assignmentId as string);
  if (!id || !assignmentId) {
    res.status(400).json({ message: "Invalid ID" });
    return;
  }
  await removeAssignment(id, assignmentId);
  res.status(204).end();
});

// GET /api/assessments/:id/submissions
export const getSubmissions = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }
  const rows = await listSubmissions(id);
  res.json(rows);
});

// GET /api/assessments/:id/submissions/:attemptId
export const getSubmissionById = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }
  const payload = await getSubmission(id, req.params.attemptId as string);
  res.json(payload);
});

// PATCH /api/assessments/:id/submissions/:attemptId/answers/:answerId
export const markAnswerHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const answerId = parseNumber(req.params.answerId as string);
  if (!id || !answerId) {
    res.status(400).json({ message: "Invalid ID" });
    return;
  }
  const updated = await markAnswer(
    id,
    req.params.attemptId as string,
    answerId,
    req.body,
    req.user!.id,
  );
  res.json(updated);
});

// POST /api/assessments/:id/submissions/:attemptId/finalize-marking
export const finalizeMarkingHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }
  const updated = await finalizeMarking(
    id,
    req.params.attemptId as string,
    req.user!.id,
  );
  res.json(updated);
});

// GET /api/assessments/:id/result
export const getPaperResultHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }
  const result = await getPaperResult(id, req.user!.id);
  res.json(result);
});

// GET /api/assessments/:id/latest-released-attempt
export const getLatestReleasedAttempt = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }
  const result = await getLatestReleasedAttemptForUser(id, req.user!.id);
  res.json(result);
});

// PATCH /api/assessments/:id  (update metadata — draft only)
export const updateAssessmentHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid assessment ID" }); return; }
  const updated = await updatePaper(id, req.body);
  res.json(updated);
});

// DELETE /api/assessments/:id  (delete — draft only)
export const deleteAssessmentHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) { res.status(400).json({ message: "Invalid assessment ID" }); return; }
  await deletePaper(id);
  res.status(204).end();
});

// PATCH /api/assessments/:id/assignments/:assignmentId  (update assignment window / attempts)
export const updateAssignmentHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  const assignmentId = parseNumber(req.params.assignmentId as string);
  if (!id || !assignmentId) { res.status(400).json({ message: "Invalid ID" }); return; }
  const updated = await updateAssignment(id, assignmentId, req.body);
  res.json(updated);
});
