import { and, desc, eq, isNull } from "drizzle-orm";
import { db } from "../core/database/index.js";
import {
  curricula,
  grades,
  topics,
  learningOutcomes,
  subjects,
} from "../core/database/schema/index.js";

// ============ CURRICULA ============

type CreateCurriculumInput = {
  name: string;
  country: string;
  description?: string;
  isActive?: boolean;
};

type UpdateCurriculumInput = Partial<CreateCurriculumInput>;

export async function listCurricula() {
  return db.select().from(curricula).orderBy(curricula.name);
}

export async function getCurriculumById(id: number) {
  const [curriculum] = await db
    .select()
    .from(curricula)
    .where(eq(curricula.id, id));
  return curriculum ?? null;
}

export async function createCurriculum(input: CreateCurriculumInput) {
  const [created] = await db
    .insert(curricula)
    .values({
      name: input.name,
      country: input.country,
      description: input.description ?? null,
      isActive: input.isActive ?? true,
    })
    .returning();
  return created;
}

export async function updateCurriculum(id: number, input: UpdateCurriculumInput) {
  const updateData: Record<string, any> = {};
  if (input.name !== undefined) updateData.name = input.name;
  if (input.country !== undefined) updateData.country = input.country;
  if (input.description !== undefined) updateData.description = input.description;
  if (input.isActive !== undefined) updateData.isActive = input.isActive;

  if (Object.keys(updateData).length === 0) return getCurriculumById(id);

  const [updated] = await db
    .update(curricula)
    .set(updateData)
    .where(eq(curricula.id, id))
    .returning();
  return updated ?? null;
}

export async function deleteCurriculum(id: number) {
  const [deleted] = await db
    .delete(curricula)
    .where(eq(curricula.id, id))
    .returning();
  return deleted ?? null;
}

// ============ GRADES ============

type CreateGradeInput = {
  curriculumId: number;
  level: number;
  label: string;
};

type UpdateGradeInput = Partial<CreateGradeInput>;

type ListGradesInput = {
  curriculumId?: number;
};

export async function listGrades(input: ListGradesInput = {}) {
  const conditions: any[] = [];
  if (input.curriculumId) {
    conditions.push(eq(grades.curriculumId, input.curriculumId));
  }

  let query = db
    .select({
      id: grades.id,
      curriculumId: grades.curriculumId,
      curriculumName: curricula.name,
      level: grades.level,
      label: grades.label,
      createdAt: grades.createdAt,
    })
    .from(grades)
    .$dynamic()
    .innerJoin(curricula, eq(grades.curriculumId, curricula.id))
    .orderBy(grades.level);

  if (conditions.length > 0) {
    query = query.where(and(...conditions));
  }

  return query;
}

export async function getGradeById(id: number) {
  const [grade] = await db
    .select({
      id: grades.id,
      curriculumId: grades.curriculumId,
      curriculumName: curricula.name,
      level: grades.level,
      label: grades.label,
      createdAt: grades.createdAt,
    })
    .from(grades)
    .innerJoin(curricula, eq(grades.curriculumId, curricula.id))
    .where(eq(grades.id, id));
  return grade ?? null;
}

export async function createGrade(input: CreateGradeInput) {
  const [created] = await db
    .insert(grades)
    .values({
      curriculumId: input.curriculumId,
      level: input.level,
      label: input.label,
    })
    .returning();
  return created;
}

export async function updateGrade(id: number, input: UpdateGradeInput) {
  const updateData: Record<string, any> = {};
  if (input.curriculumId !== undefined) updateData.curriculumId = input.curriculumId;
  if (input.level !== undefined) updateData.level = input.level;
  if (input.label !== undefined) updateData.label = input.label;

  if (Object.keys(updateData).length === 0) return getGradeById(id);

  const [updated] = await db
    .update(grades)
    .set(updateData)
    .where(eq(grades.id, id))
    .returning();
  return updated ?? null;
}

export async function deleteGrade(id: number) {
  const [deleted] = await db
    .delete(grades)
    .where(eq(grades.id, id))
    .returning();
  return deleted ?? null;
}

// ============ TOPICS ============

type CreateTopicInput = {
  subjectId: number;
  gradeId: number;
  parentTopicId?: number;
  title: string;
  description?: string;
  termNumber?: number;
  capsReference?: string;
  order?: number;
  weighting?: number;
};

type UpdateTopicInput = Partial<CreateTopicInput>;

type ListTopicsInput = {
  subjectId?: number;
  gradeId?: number;
  parentTopicId?: number | null;
  termNumber?: number;
};

export async function listTopics(input: ListTopicsInput = {}) {
  const conditions: any[] = [];

  if (input.subjectId) {
    conditions.push(eq(topics.subjectId, input.subjectId));
  }
  if (input.gradeId) {
    conditions.push(eq(topics.gradeId, input.gradeId));
  }
  if (input.termNumber) {
    conditions.push(eq(topics.termNumber, input.termNumber));
  }
  if (input.parentTopicId !== undefined) {
    if (input.parentTopicId === null) {
      conditions.push(isNull(topics.parentTopicId));
    } else {
      conditions.push(eq(topics.parentTopicId, input.parentTopicId));
    }
  }

  let query = db
    .select({
      id: topics.id,
      subjectId: topics.subjectId,
      subjectName: subjects.name,
      gradeId: topics.gradeId,
      gradeLabel: grades.label,
      parentTopicId: topics.parentTopicId,
      title: topics.title,
      description: topics.description,
      termNumber: topics.termNumber,
      capsReference: topics.capsReference,
      order: topics.order,
      weighting: topics.weighting,
      createdAt: topics.createdAt,
    })
    .from(topics)
    .$dynamic()
    .innerJoin(subjects, eq(topics.subjectId, subjects.id))
    .innerJoin(grades, eq(topics.gradeId, grades.id))
    .orderBy(topics.order, topics.title);

  if (conditions.length > 0) {
    query = query.where(and(...conditions));
  }

  return query;
}

export async function getTopicById(id: number) {
  const [topic] = await db
    .select({
      id: topics.id,
      subjectId: topics.subjectId,
      subjectName: subjects.name,
      gradeId: topics.gradeId,
      gradeLabel: grades.label,
      parentTopicId: topics.parentTopicId,
      title: topics.title,
      description: topics.description,
      termNumber: topics.termNumber,
      capsReference: topics.capsReference,
      order: topics.order,
      weighting: topics.weighting,
      createdAt: topics.createdAt,
    })
    .from(topics)
    .innerJoin(subjects, eq(topics.subjectId, subjects.id))
    .innerJoin(grades, eq(topics.gradeId, grades.id))
    .where(eq(topics.id, id));
  return topic ?? null;
}

export async function getTopicWithSubtopics(id: number) {
  const topic = await getTopicById(id);
  if (!topic) return null;

  const subtopics = await db
    .select()
    .from(topics)
    .where(eq(topics.parentTopicId, id))
    .orderBy(topics.order, topics.title);

  const outcomes = await db
    .select()
    .from(learningOutcomes)
    .where(eq(learningOutcomes.topicId, id))
    .orderBy(learningOutcomes.code);

  return { ...topic, subtopics, outcomes };
}

export async function createTopic(input: CreateTopicInput) {
  const [created] = await db
    .insert(topics)
    .values({
      subjectId: input.subjectId,
      gradeId: input.gradeId,
      parentTopicId: input.parentTopicId ?? null,
      title: input.title,
      description: input.description ?? null,
      termNumber: input.termNumber ?? null,
      capsReference: input.capsReference ?? null,
      order: input.order ?? 0,
      weighting: input.weighting ?? null,
    })
    .returning();
  return created;
}

export async function updateTopic(id: number, input: UpdateTopicInput) {
  const updateData: Record<string, any> = {};
  if (input.subjectId !== undefined) updateData.subjectId = input.subjectId;
  if (input.gradeId !== undefined) updateData.gradeId = input.gradeId;
  if (input.parentTopicId !== undefined) updateData.parentTopicId = input.parentTopicId;
  if (input.title !== undefined) updateData.title = input.title;
  if (input.description !== undefined) updateData.description = input.description;
  if (input.termNumber !== undefined) updateData.termNumber = input.termNumber;
  if (input.capsReference !== undefined) updateData.capsReference = input.capsReference;
  if (input.order !== undefined) updateData.order = input.order;
  if (input.weighting !== undefined) updateData.weighting = input.weighting;

  if (Object.keys(updateData).length === 0) return getTopicById(id);

  const [updated] = await db
    .update(topics)
    .set(updateData)
    .where(eq(topics.id, id))
    .returning();
  return updated ?? null;
}

export async function deleteTopic(id: number) {
  const [deleted] = await db
    .delete(topics)
    .where(eq(topics.id, id))
    .returning();
  return deleted ?? null;
}

// ============ LEARNING OUTCOMES ============

type CreateLearningOutcomeInput = {
  topicId: number;
  code?: string;
  description: string;
  bloomsLevel?: string;
};

type UpdateLearningOutcomeInput = Partial<CreateLearningOutcomeInput>;

export async function listLearningOutcomes(topicId: number) {
  return db
    .select()
    .from(learningOutcomes)
    .where(eq(learningOutcomes.topicId, topicId))
    .orderBy(learningOutcomes.code);
}

export async function getLearningOutcomeById(id: number) {
  const [outcome] = await db
    .select()
    .from(learningOutcomes)
    .where(eq(learningOutcomes.id, id));
  return outcome ?? null;
}

export async function createLearningOutcome(input: CreateLearningOutcomeInput) {
  const [created] = await db
    .insert(learningOutcomes)
    .values({
      topicId: input.topicId,
      code: input.code ?? null,
      description: input.description,
      bloomsLevel: input.bloomsLevel ?? null,
    })
    .returning();
  return created;
}

export async function updateLearningOutcome(id: number, input: UpdateLearningOutcomeInput) {
  const updateData: Record<string, any> = {};
  if (input.topicId !== undefined) updateData.topicId = input.topicId;
  if (input.code !== undefined) updateData.code = input.code;
  if (input.description !== undefined) updateData.description = input.description;
  if (input.bloomsLevel !== undefined) updateData.bloomsLevel = input.bloomsLevel;

  if (Object.keys(updateData).length === 0) return getLearningOutcomeById(id);

  const [updated] = await db
    .update(learningOutcomes)
    .set(updateData)
    .where(eq(learningOutcomes.id, id))
    .returning();
  return updated ?? null;
}

export async function deleteLearningOutcome(id: number) {
  const [deleted] = await db
    .delete(learningOutcomes)
    .where(eq(learningOutcomes.id, id))
    .returning();
  return deleted ?? null;
}
