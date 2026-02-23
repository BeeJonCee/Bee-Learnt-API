import { and, desc, eq, ilike, inArray, sql } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import { questionBankItems, subjects, modules } from "../../core/database/schema/index.js";

export type QuestionType =
  | "multiple_choice"
  | "short_answer"
  | "essay";

export type QuestionDifficulty = "easy" | "medium" | "hard" | "adaptive";

export type QuestionSource =
  | "manual"
  | "nsc_past_paper"
  | "exemplar"
  | "textbook"
  | "ai_generated"
  | "imported";

export interface QuestionOption {
  id: string;
  text: string;
  imageUrl?: string;
  isCorrect?: boolean;
}

export interface CorrectAnswer {
  type: "single" | "multi" | "text" | "numeric" | "pairs" | "order";
  value: string | string[] | number | MatchPair[] | string[];
  tolerance?: number;
  caseSensitive?: boolean;
}

export interface MatchPair {
  left: string;
  right: string;
}

type OptionDebugItem = {
  id: string;
  text: string;
  imageUrl?: string;
  isPlaceholder: boolean;
};

type OptionDebugResult = {
  parsedFrom: string;
  items: OptionDebugItem[];
};

type ListQuestionsInput = {
  subjectId?: number;
  moduleId?: number;
  difficulty?: QuestionDifficulty;
  type?: QuestionType;
  source?: QuestionSource;
  tags?: string[];
  search?: string;
  isActive?: boolean;
  limit?: number;
  offset?: number;
};

type CreateQuestionInput = {
  subjectId: number;
  moduleId?: number;
  type: QuestionType;
  difficulty?: QuestionDifficulty;
  questionText: string;
  questionHtml?: string;
  imageUrl?: string;
  options?: QuestionOption[];
  correctAnswer?: CorrectAnswer;
  explanation?: string;
  solutionSteps?: string[];
  points?: number;
  timeLimitSeconds?: number;
  source?: QuestionSource;
  sourceReference?: string;
  tags?: string[];
  language?: string;
};

type UpdateQuestionInput = Partial<CreateQuestionInput> & {
  isActive?: boolean;
  reviewedBy?: string;
  reviewedAt?: Date;
};

type RandomQuestionsInput = {
  subjectId?: number;
  moduleId?: number;
  difficulty?: QuestionDifficulty;
  type?: QuestionType;
  count: number;
  excludeIds?: number[];
};

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function toDisplayText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  if (typeof value === "object") {
    const payload = value as Record<string, unknown>;
    if (payload.text !== undefined) return toDisplayText(payload.text);
    if (payload.label !== undefined) return toDisplayText(payload.label);
    if (payload.value !== undefined) return toDisplayText(payload.value);
    return safeStringify(value);
  }
  return String(value);
}

function tryParseJson(value: unknown): unknown {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  if (!trimmed) return value;
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return value;
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function readOptionText(option: Record<string, unknown>): string {
  const direct = [
    option.text,
    option.label,
    option.value,
    option.optionText,
    option.option_text,
    option.option,
    option.content,
    option.answer,
    option.title,
    option.name,
    option.description,
  ];

  for (const candidate of direct) {
    const text = toDisplayText(candidate).trim();
    if (text.length > 0) return text;
  }

  return "";
}

function readOptionImageUrl(option: Record<string, unknown>): string | undefined {
  const candidate = option.imageUrl ?? option.image_url ?? option.image;
  if (typeof candidate !== "string") return undefined;
  const trimmed = candidate.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function parseOptionEntry(
  entry: unknown,
  index: number,
  explicitId?: string
): OptionDebugItem {
  const normalized = tryParseJson(entry);

  if (
    typeof normalized === "string" ||
    typeof normalized === "number" ||
    typeof normalized === "boolean"
  ) {
    const text = toDisplayText(normalized).trim();
    return {
      id: explicitId ?? String(index),
      text: text || `Option ${index + 1}`,
      isPlaceholder: text.length === 0,
    };
  }

  if (normalized && typeof normalized === "object" && !Array.isArray(normalized)) {
    const option = normalized as Record<string, unknown>;
    const idCandidate =
      option.id ?? option.key ?? option.code ?? explicitId ?? index;
    const id = toDisplayText(idCandidate).trim() || String(index);
    const text = readOptionText(option);
    return {
      id,
      text: text || `Option ${index + 1}`,
      imageUrl: readOptionImageUrl(option),
      isPlaceholder: text.length === 0,
    };
  }

  const fallback = toDisplayText(normalized).trim();
  return {
    id: explicitId ?? String(index),
    text: fallback || `Option ${index + 1}`,
    isPlaceholder: fallback.length === 0,
  };
}

function parseOptionsForDebug(raw: unknown, source = "root"): OptionDebugResult {
  const normalized = tryParseJson(raw);
  if (!normalized) {
    return { parsedFrom: source, items: [] };
  }

  if (Array.isArray(normalized)) {
    return {
      parsedFrom: source,
      items: normalized.map((entry, index) => parseOptionEntry(entry, index)),
    };
  }

  if (typeof normalized === "object" && normalized !== null) {
    const obj = normalized as Record<string, unknown>;
    const nestedKeys = ["options", "choices", "items", "values"] as const;
    for (const key of nestedKeys) {
      if (obj[key] !== undefined) {
        const nested = parseOptionsForDebug(obj[key], `${source}.${key}`);
        if (nested.items.length > 0) return nested;
      }
    }

    const mapEntries = Object.entries(obj).filter(
      ([key]) =>
        ![
          "type",
          "left",
          "right",
          "pairs",
          "shuffleLeft",
          "shuffleRight",
        ].includes(key)
    );
    if (mapEntries.length > 0) {
      return {
        parsedFrom: `${source}.map`,
        items: mapEntries.map(([key, value], index) =>
          parseOptionEntry(value, index, key)
        ),
      };
    }
  }

  return { parsedFrom: source, items: [] };
}

export async function listQuestions(input: ListQuestionsInput) {
  const conditions: any[] = [];

  if (input.subjectId) {
    conditions.push(eq(questionBankItems.subjectId, input.subjectId));
  }
  if (input.moduleId) {
    conditions.push(eq(questionBankItems.moduleId, input.moduleId));
  }
  if (input.difficulty) {
    conditions.push(eq(questionBankItems.difficulty, input.difficulty));
  }
  if (input.type) {
    conditions.push(eq(questionBankItems.type, input.type));
  }
  if (input.source) {
    conditions.push(eq(questionBankItems.source, input.source));
  }
  if (input.isActive !== undefined) {
    conditions.push(eq(questionBankItems.isActive, input.isActive));
  }
  if (input.search) {
    conditions.push(ilike(questionBankItems.questionText, `%${input.search}%`));
  }
  if (input.tags && input.tags.length > 0) {
    // Check if any of the provided tags are in the question's tags array
    conditions.push(
      sql`${questionBankItems.tags} ?| array[${sql.join(
        input.tags.map((t) => sql`${t}`),
        sql`, `
      )}]`
    );
  }

  const limit = input.limit ?? 50;
  const offset = input.offset ?? 0;

  let query = db
    .select({
      id: questionBankItems.id,
      subjectId: questionBankItems.subjectId,
      subjectName: subjects.name,
      moduleId: questionBankItems.moduleId,
      moduleName: modules.title,
      type: questionBankItems.type,
      difficulty: questionBankItems.difficulty,
      questionText: questionBankItems.questionText,
      questionHtml: questionBankItems.questionHtml,
      imageUrl: questionBankItems.imageUrl,
      options: questionBankItems.options,
      points: questionBankItems.points,
      timeLimitSeconds: questionBankItems.timeLimitSeconds,
      source: questionBankItems.source,
      sourceReference: questionBankItems.sourceReference,
      tags: questionBankItems.tags,
      language: questionBankItems.language,
      isActive: questionBankItems.isActive,
      createdAt: questionBankItems.createdAt,
      updatedAt: questionBankItems.updatedAt,
    })
    .from(questionBankItems)
    .$dynamic()
    .innerJoin(subjects, eq(questionBankItems.subjectId, subjects.id))
    .leftJoin(modules, eq(questionBankItems.moduleId, modules.id))
    .orderBy(desc(questionBankItems.createdAt))
    .limit(limit)
    .offset(offset);

  if (conditions.length > 0) {
    query = query.where(and(...conditions));
  }

  const items = await query;

  // Get total count for pagination
  let countQuery = db
    .select({ count: sql<number>`count(*)::int` })
    .from(questionBankItems)
    .$dynamic();

  if (conditions.length > 0) {
    countQuery = countQuery.where(and(...conditions));
  }

  const [{ count }] = await countQuery;

  return { items, total: count, limit, offset };
}

export async function getQuestionById(id: number) {
  const [question] = await db
    .select({
      id: questionBankItems.id,
      subjectId: questionBankItems.subjectId,
      subjectName: subjects.name,
      moduleId: questionBankItems.moduleId,
      moduleName: modules.title,
      type: questionBankItems.type,
      difficulty: questionBankItems.difficulty,
      questionText: questionBankItems.questionText,
      questionHtml: questionBankItems.questionHtml,
      imageUrl: questionBankItems.imageUrl,
      options: questionBankItems.options,
      correctAnswer: questionBankItems.correctAnswer,
      explanation: questionBankItems.explanation,
      solutionSteps: questionBankItems.solutionSteps,
      points: questionBankItems.points,
      timeLimitSeconds: questionBankItems.timeLimitSeconds,
      source: questionBankItems.source,
      sourceReference: questionBankItems.sourceReference,
      tags: questionBankItems.tags,
      language: questionBankItems.language,
      isActive: questionBankItems.isActive,
      createdBy: questionBankItems.createdBy,
      reviewedBy: questionBankItems.reviewedBy,
      reviewedAt: questionBankItems.reviewedAt,
      createdAt: questionBankItems.createdAt,
      updatedAt: questionBankItems.updatedAt,
    })
    .from(questionBankItems)
    .innerJoin(subjects, eq(questionBankItems.subjectId, subjects.id))
    .leftJoin(modules, eq(questionBankItems.moduleId, modules.id))
    .where(eq(questionBankItems.id, id));

  return question ?? null;
}

export async function getQuestionOptionsDebug(id: number) {
  const [question] = await db
    .select({
      id: questionBankItems.id,
      type: questionBankItems.type,
      questionText: questionBankItems.questionText,
      options: questionBankItems.options,
      correctAnswer: questionBankItems.correctAnswer,
      subjectId: questionBankItems.subjectId,
      moduleId: questionBankItems.moduleId,
      isActive: questionBankItems.isActive,
      updatedAt: questionBankItems.updatedAt,
    })
    .from(questionBankItems)
    .where(eq(questionBankItems.id, id));

  if (!question) return null;

  const parsed = parseOptionsForDebug(question.options);
  const placeholderCount = parsed.items.filter((item) => item.isPlaceholder).length;

  return {
    question: {
      id: question.id,
      type: question.type,
      questionText: question.questionText,
      subjectId: question.subjectId,
      moduleId: question.moduleId,
      isActive: question.isActive,
      updatedAt: question.updatedAt,
    },
    raw: {
      options: question.options,
      correctAnswer: question.correctAnswer,
      optionsType: question.options === null ? "null" : typeof question.options,
    },
    normalized: {
      parsedFrom: parsed.parsedFrom,
      optionCount: parsed.items.length,
      placeholderCount,
      items: parsed.items,
    },
  };
}

export async function createQuestion(input: CreateQuestionInput, createdBy: string) {
  const [question] = await db
    .insert(questionBankItems)
    .values({
      subjectId: input.subjectId,
      moduleId: input.moduleId ?? null,
      type: input.type,
      difficulty: input.difficulty ?? "medium",
      questionText: input.questionText,
      questionHtml: input.questionHtml ?? null,
      imageUrl: input.imageUrl ?? null,
      options: (input.options as any) ?? null,
      correctAnswer: (input.correctAnswer as any) ?? null,
      explanation: input.explanation ?? null,
      solutionSteps: input.solutionSteps ?? [],
      points: input.points ?? 1,
      timeLimitSeconds: input.timeLimitSeconds ?? null,
      source: input.source ?? "manual",
      sourceReference: input.sourceReference ?? null,
      tags: input.tags ?? [],
      language: input.language ?? "en",
      isActive: true,
      createdBy,
      updatedAt: new Date(),
    })
    .returning();

  return question;
}

export async function updateQuestion(id: number, input: UpdateQuestionInput) {
  const updateData: Record<string, any> = { updatedAt: new Date() };

  if (input.subjectId !== undefined) updateData.subjectId = input.subjectId;
  if (input.moduleId !== undefined) updateData.moduleId = input.moduleId;
  if (input.type !== undefined) updateData.type = input.type;
  if (input.difficulty !== undefined) updateData.difficulty = input.difficulty;
  if (input.questionText !== undefined) updateData.questionText = input.questionText;
  if (input.questionHtml !== undefined) updateData.questionHtml = input.questionHtml;
  if (input.imageUrl !== undefined) updateData.imageUrl = input.imageUrl;
  if (input.options !== undefined) updateData.options = input.options;
  if (input.correctAnswer !== undefined) updateData.correctAnswer = input.correctAnswer;
  if (input.explanation !== undefined) updateData.explanation = input.explanation;
  if (input.solutionSteps !== undefined) updateData.solutionSteps = input.solutionSteps;
  if (input.points !== undefined) updateData.points = input.points;
  if (input.timeLimitSeconds !== undefined) updateData.timeLimitSeconds = input.timeLimitSeconds;
  if (input.source !== undefined) updateData.source = input.source;
  if (input.sourceReference !== undefined) updateData.sourceReference = input.sourceReference;
  if (input.tags !== undefined) updateData.tags = input.tags;
  if (input.language !== undefined) updateData.language = input.language;
  if (input.isActive !== undefined) updateData.isActive = input.isActive;
  if (input.reviewedBy !== undefined) updateData.reviewedBy = input.reviewedBy;
  if (input.reviewedAt !== undefined) updateData.reviewedAt = input.reviewedAt;

  const [updated] = await db
    .update(questionBankItems)
    .set(updateData)
    .where(eq(questionBankItems.id, id))
    .returning();

  return updated ?? null;
}

export async function deleteQuestion(id: number) {
  // Soft delete by setting isActive to false
  const [deleted] = await db
    .update(questionBankItems)
    .set({ isActive: false, updatedAt: new Date() })
    .where(eq(questionBankItems.id, id))
    .returning();

  return deleted ?? null;
}

export async function getRandomQuestions(input: RandomQuestionsInput) {
  const conditions: any[] = [eq(questionBankItems.isActive, true)];

  if (input.subjectId) {
    conditions.push(eq(questionBankItems.subjectId, input.subjectId));
  }
  if (input.moduleId) {
    conditions.push(eq(questionBankItems.moduleId, input.moduleId));
  }
  if (input.difficulty) {
    conditions.push(eq(questionBankItems.difficulty, input.difficulty));
  }
  if (input.type) {
    conditions.push(eq(questionBankItems.type, input.type));
  }
  if (input.excludeIds && input.excludeIds.length > 0) {
    conditions.push(sql`${questionBankItems.id} NOT IN (${sql.join(input.excludeIds.map(id => sql`${id}`), sql`, `)})`);
  }

  const questions = await db
    .select({
      id: questionBankItems.id,
      subjectId: questionBankItems.subjectId,
      moduleId: questionBankItems.moduleId,
      type: questionBankItems.type,
      difficulty: questionBankItems.difficulty,
      questionText: questionBankItems.questionText,
      questionHtml: questionBankItems.questionHtml,
      imageUrl: questionBankItems.imageUrl,
      options: questionBankItems.options,
      points: questionBankItems.points,
      timeLimitSeconds: questionBankItems.timeLimitSeconds,
      tags: questionBankItems.tags,
    })
    .from(questionBankItems)
    .where(and(...conditions))
    .orderBy(sql`RANDOM()`)
    .limit(input.count);

  return questions;
}

export async function bulkCreateQuestions(
  questions: CreateQuestionInput[],
  createdBy: string
) {
  if (questions.length === 0) return [];

  const values = questions.map((q) => ({
    subjectId: q.subjectId,
    moduleId: q.moduleId ?? null,
    type: q.type,
    difficulty: q.difficulty ?? "medium",
    questionText: q.questionText,
    questionHtml: q.questionHtml ?? null,
    imageUrl: q.imageUrl ?? null,
    options: (q.options as any) ?? null,
    correctAnswer: (q.correctAnswer as any) ?? null,
    explanation: q.explanation ?? null,
    solutionSteps: q.solutionSteps ?? [],
    points: q.points ?? 1,
    timeLimitSeconds: q.timeLimitSeconds ?? null,
    source: q.source ?? "imported",
    sourceReference: q.sourceReference ?? null,
    tags: q.tags ?? [],
    language: q.language ?? "en",
    isActive: true,
    createdBy,
    updatedAt: new Date(),
  }));

  const created = await db.insert(questionBankItems).values(values).returning();

  return created;
}

export async function getQuestionStats(subjectId?: number) {
  const conditions: any[] = [];
  if (subjectId) {
    conditions.push(eq(questionBankItems.subjectId, subjectId));
  }

  const baseQuery = conditions.length > 0 ? and(...conditions) : undefined;

  const [stats] = await db
    .select({
      total: sql<number>`count(*)::int`,
      active: sql<number>`count(*) filter (where ${questionBankItems.isActive} = true)::int`,
      easy: sql<number>`count(*) filter (where ${questionBankItems.difficulty} = 'easy')::int`,
      medium: sql<number>`count(*) filter (where ${questionBankItems.difficulty} = 'medium')::int`,
      hard: sql<number>`count(*) filter (where ${questionBankItems.difficulty} = 'hard')::int`,
      multipleChoice: sql<number>`count(*) filter (where ${questionBankItems.type} = 'multiple_choice')::int`,
      shortAnswer: sql<number>`count(*) filter (where ${questionBankItems.type} = 'short_answer')::int`,
      essay: sql<number>`count(*) filter (where ${questionBankItems.type} = 'essay')::int`,
    })
    .from(questionBankItems)
    .where(baseQuery);

  return stats;
}
