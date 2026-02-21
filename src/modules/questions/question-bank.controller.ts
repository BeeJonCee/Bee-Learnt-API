import { asyncHandler } from "../../core/middleware/async-handler.js";
import {
  listQuestions,
  getQuestionById,
  createQuestion,
  updateQuestion,
  deleteQuestion,
  getRandomQuestions,
  bulkCreateQuestions,
  getQuestionStats,
} from "./question-bank.service.js";
import { parseNumber } from "../../shared/utils/parse.js";

export const list = asyncHandler(async (req, res) => {
  const {
    subjectId,
    moduleId,
    difficulty,
    type,
    source,
    tags,
    search,
    isActive,
    limit,
    offset,
  } = req.query;

  const result = await listQuestions({
    subjectId: subjectId ? Number(subjectId) : undefined,
    moduleId: moduleId ? Number(moduleId) : undefined,
    difficulty: difficulty as any,
    type: type as any,
    source: source as any,
    tags: tags ? (Array.isArray(tags) ? tags : [tags]) as string[] : undefined,
    search: search as string,
    isActive: isActive !== undefined ? isActive === "true" : undefined,
    limit: limit ? Number(limit) : undefined,
    offset: offset ? Number(offset) : undefined,
  });

  res.json(result);
});

export const getById = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid question ID" });
    return;
  }

  const question = await getQuestionById(id);
  if (!question) {
    res.status(404).json({ message: "Question not found" });
    return;
  }

  res.json(question);
});

export const create = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const question = await createQuestion(req.body, userId);
  res.status(201).json(question);
});

export const update = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid question ID" });
    return;
  }

  const existing = await getQuestionById(id);
  if (!existing) {
    res.status(404).json({ message: "Question not found" });
    return;
  }

  const updated = await updateQuestion(id, req.body);
  res.json(updated);
});

export const remove = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid question ID" });
    return;
  }

  const existing = await getQuestionById(id);
  if (!existing) {
    res.status(404).json({ message: "Question not found" });
    return;
  }

  await deleteQuestion(id);
  res.json({ message: "Question deleted" });
});

export const random = asyncHandler(async (req, res) => {
  const { subjectId, moduleId, difficulty, type, count, excludeIds } = req.query;

  const questions = await getRandomQuestions({
    subjectId: subjectId ? Number(subjectId) : undefined,
    moduleId: moduleId ? Number(moduleId) : undefined,
    difficulty: difficulty as any,
    type: type as any,
    count: count ? Number(count) : 10,
    excludeIds: excludeIds
      ? (Array.isArray(excludeIds) ? excludeIds : [excludeIds]).map(Number)
      : undefined,
  });

  res.json(questions);
});

export const bulkImport = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const { questions } = req.body;

  if (!Array.isArray(questions) || questions.length === 0) {
    res.status(400).json({ message: "Questions array is required" });
    return;
  }

  if (questions.length > 500) {
    res.status(400).json({ message: "Maximum 500 questions per import" });
    return;
  }

  const created = await bulkCreateQuestions(questions, userId);
  res.status(201).json({
    message: `${created.length} questions imported`,
    count: created.length,
    questions: created,
  });
});

export const stats = asyncHandler(async (req, res) => {
  const { subjectId } = req.query;
  const result = await getQuestionStats(subjectId ? Number(subjectId) : undefined);
  res.json(result);
});

export const review = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid question ID" });
    return;
  }

  const existing = await getQuestionById(id);
  if (!existing) {
    res.status(404).json({ message: "Question not found" });
    return;
  }

  const userId = req.user!.id;
  const updated = await updateQuestion(id, {
    reviewedBy: userId,
    reviewedAt: new Date(),
  });

  res.json(updated);
});
