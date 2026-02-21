import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber } from "../shared/utils/parse.js";
import {
  listCurricula,
  getCurriculumById,
  createCurriculum,
  updateCurriculum,
  deleteCurriculum,
  listGrades,
  getGradeById,
  createGrade,
  updateGrade,
  deleteGrade,
  listTopics,
  getTopicById,
  getTopicWithSubtopics,
  createTopic,
  updateTopic,
  deleteTopic,
  listLearningOutcomes,
  getLearningOutcomeById,
  createLearningOutcome,
  updateLearningOutcome,
  deleteLearningOutcome,
} from "../services/curriculum.service.js";

// ============ CURRICULA ============

export const listCurriculaHandler = asyncHandler(async (_req, res) => {
  const result = await listCurricula();
  res.json(result);
});

export const getCurriculumHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid curriculum ID" });
    return;
  }

  const curriculum = await getCurriculumById(id);
  if (!curriculum) {
    res.status(404).json({ message: "Curriculum not found" });
    return;
  }

  res.json(curriculum);
});

export const createCurriculumHandler = asyncHandler(async (req, res) => {
  const created = await createCurriculum(req.body);
  res.status(201).json(created);
});

export const updateCurriculumHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid curriculum ID" });
    return;
  }

  const existing = await getCurriculumById(id);
  if (!existing) {
    res.status(404).json({ message: "Curriculum not found" });
    return;
  }

  const updated = await updateCurriculum(id, req.body);
  res.json(updated);
});

export const deleteCurriculumHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid curriculum ID" });
    return;
  }

  const existing = await getCurriculumById(id);
  if (!existing) {
    res.status(404).json({ message: "Curriculum not found" });
    return;
  }

  await deleteCurriculum(id);
  res.json({ message: "Curriculum deleted" });
});

// ============ GRADES ============

export const listGradesHandler = asyncHandler(async (req, res) => {
  const curriculumId = req.query.curriculumId as string | undefined;
  const result = await listGrades({
    curriculumId: curriculumId ? Number(curriculumId) : undefined,
  });
  res.json(result);
});

export const getGradeHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid grade ID" });
    return;
  }

  const grade = await getGradeById(id);
  if (!grade) {
    res.status(404).json({ message: "Grade not found" });
    return;
  }

  res.json(grade);
});

export const createGradeHandler = asyncHandler(async (req, res) => {
  const created = await createGrade(req.body);
  res.status(201).json(created);
});

export const updateGradeHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid grade ID" });
    return;
  }

  const existing = await getGradeById(id);
  if (!existing) {
    res.status(404).json({ message: "Grade not found" });
    return;
  }

  const updated = await updateGrade(id, req.body);
  res.json(updated);
});

export const deleteGradeHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid grade ID" });
    return;
  }

  const existing = await getGradeById(id);
  if (!existing) {
    res.status(404).json({ message: "Grade not found" });
    return;
  }

  await deleteGrade(id);
  res.json({ message: "Grade deleted" });
});

// ============ TOPICS ============

export const listTopicsHandler = asyncHandler(async (req, res) => {
  const subjectId = req.query.subjectId as string | undefined;
  const gradeId = req.query.gradeId as string | undefined;
  const parentTopicId = req.query.parentTopicId as string | undefined;
  const termNumber = req.query.termNumber as string | undefined;
  const result = await listTopics({
    subjectId: subjectId ? Number(subjectId) : undefined,
    gradeId: gradeId ? Number(gradeId) : undefined,
    parentTopicId: parentTopicId ? Number(parentTopicId) : undefined,
    termNumber: termNumber ? Number(termNumber) : undefined,
  });
  res.json(result);
});

export const getTopicHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid topic ID" });
    return;
  }

  const topic = await getTopicWithSubtopics(id);
  if (!topic) {
    res.status(404).json({ message: "Topic not found" });
    return;
  }

  res.json(topic);
});

export const createTopicHandler = asyncHandler(async (req, res) => {
  const created = await createTopic(req.body);
  res.status(201).json(created);
});

export const updateTopicHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid topic ID" });
    return;
  }

  const existing = await getTopicById(id);
  if (!existing) {
    res.status(404).json({ message: "Topic not found" });
    return;
  }

  const updated = await updateTopic(id, req.body);
  res.json(updated);
});

export const deleteTopicHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid topic ID" });
    return;
  }

  const existing = await getTopicById(id);
  if (!existing) {
    res.status(404).json({ message: "Topic not found" });
    return;
  }

  await deleteTopic(id);
  res.json({ message: "Topic deleted" });
});

// ============ LEARNING OUTCOMES ============

export const listOutcomesHandler = asyncHandler(async (req, res) => {
  const topicId = parseNumber(req.params.topicId as string);
  if (!topicId) {
    res.status(400).json({ message: "Invalid topic ID" });
    return;
  }

  const result = await listLearningOutcomes(topicId);
  res.json(result);
});

export const getOutcomeHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid outcome ID" });
    return;
  }

  const outcome = await getLearningOutcomeById(id);
  if (!outcome) {
    res.status(404).json({ message: "Learning outcome not found" });
    return;
  }

  res.json(outcome);
});

export const createOutcomeHandler = asyncHandler(async (req, res) => {
  const topicId = parseNumber(req.params.topicId as string);
  if (!topicId) {
    res.status(400).json({ message: "Invalid topic ID" });
    return;
  }

  const created = await createLearningOutcome({ ...req.body, topicId });
  res.status(201).json(created);
});

export const updateOutcomeHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid outcome ID" });
    return;
  }

  const existing = await getLearningOutcomeById(id);
  if (!existing) {
    res.status(404).json({ message: "Learning outcome not found" });
    return;
  }

  const updated = await updateLearningOutcome(id, req.body);
  res.json(updated);
});

export const deleteOutcomeHandler = asyncHandler(async (req, res) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid outcome ID" });
    return;
  }

  const existing = await getLearningOutcomeById(id);
  if (!existing) {
    res.status(404).json({ message: "Learning outcome not found" });
    return;
  }

  await deleteLearningOutcome(id);
  res.json({ message: "Learning outcome deleted" });
});
