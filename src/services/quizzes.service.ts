import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import {
  badges,
  learningProfiles,
  quizAnswers,
  quizAttempts,
  quizQuestions,
  quizzes,
  subjects,
  userBadges,
} from "../core/database/schema/index.js";
import { getOpenAiClient } from "../clients/openai.js";
import { rateLimit } from "../shared/utils/rate-limit.js";
import { quizPromptTemplate } from "../shared/utils/quiz-prompt.js";
import { HttpError } from "../shared/utils/http-error.js";

type QuizGenerateInput = {
  subjectId: number;
  moduleId: number;
  topic: string;
  grade: number;
  capsTags: string[];
  difficulty: "easy" | "medium" | "hard" | "adaptive";
};

type QuizSubmitInput = {
  quizId: number;
  answers: Array<{ questionId: number; answer: unknown }>;
};

type QuizReviewQuestionUpdateInput = {
  id: number;
  type:
    | "multiple_choice"
    | "multi_select"
    | "true_false"
    | "short_answer"
    | "essay"
    | "numeric"
    | "matching"
    | "ordering"
    | "fill_in_blank";
  questionText: string;
  options?: unknown;
  correctAnswer?: string | null;
  explanation?: string | null;
  points?: number;
};

type QuizReviewUpdateInput = {
  title?: string;
  description?: string | null;
  difficulty?: "easy" | "medium" | "hard" | "adaptive";
  source?: string;
  capsTags?: string[];
  revealCorrectAnswers?: boolean;
  revealToParents?: boolean;
  questions?: QuizReviewQuestionUpdateInput[];
};

type QuizOption = {
  id: string;
  text: string;
};

const MIN_QUIZ_QUESTION_COUNT = 20;
const ALLOWED_QUIZ_TYPES = new Set([
  "multiple_choice",
  "multi_select",
  "true_false",
  "short_answer",
  "essay",
  "numeric",
  "matching",
  "ordering",
  "fill_in_blank",
]);

type GeneratedQuizQuestion = {
  type: string;
  questionText: string;
  options: unknown;
  correctAnswer: string | null;
  explanation: string | null;
  points: number;
};

function toNullableText(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function normalizeQuizQuestionType(value: unknown): string {
  if (typeof value !== "string") return "multiple_choice";
  const normalized = value.trim().toLowerCase();
  return ALLOWED_QUIZ_TYPES.has(normalized) ? normalized : "multiple_choice";
}

function normalizeGeneratedQuizQuestion(
  question: Record<string, unknown>,
  index: number
): GeneratedQuizQuestion {
  const textCandidate = toNullableText(question.questionText)?.trim();
  const questionText = textCandidate?.length
    ? textCandidate
    : `Practice question ${index + 1}`;

  const pointsCandidate = Number(question.points);
  const points =
    Number.isFinite(pointsCandidate) && pointsCandidate > 0
      ? Math.trunc(pointsCandidate)
      : 1;

  return {
    type: normalizeQuizQuestionType(question.type),
    questionText,
    options: Array.isArray(question.options) ? question.options : null,
    correctAnswer: toNullableText(question.correctAnswer),
    explanation: toNullableText(question.explanation),
    points,
  };
}

function ensureMinimumGeneratedQuestions(
  questions: GeneratedQuizQuestion[],
  minCount: number
) {
  if (questions.length === 0) return questions;
  if (questions.length >= minCount) return questions;

  const expanded = [...questions];
  while (expanded.length < minCount) {
    const template = questions[(expanded.length - questions.length) % questions.length];
    const cloneIndex = expanded.length + 1;
    expanded.push({
      ...template,
      questionText: `${template.questionText} (Practice ${cloneIndex})`,
    });
  }
  return expanded;
}

function parseQuizOptions(raw: unknown): QuizOption[] {
  if (!Array.isArray(raw)) return [];

  return raw.map((entry, index) => {
    if (typeof entry === "string") {
      return { id: String(index), text: entry };
    }

    if (entry && typeof entry === "object") {
      const option = entry as Record<string, unknown>;
      return {
        id: String(option.id ?? index),
        text: String(option.text ?? option.label ?? option.value ?? ""),
      };
    }

    return { id: String(index), text: String(entry) };
  });
}

function parseJsonIfNeeded(value: string | null): unknown {
  if (value === null) return null;
  const trimmed = value.trim();
  if (!trimmed) return "";
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function extractAnswerValue(answer: unknown): unknown {
  if (!answer || typeof answer !== "object" || Array.isArray(answer)) {
    return answer;
  }

  const payload = answer as Record<string, unknown>;
  if (payload.value !== undefined) return payload.value;
  if (payload.answer !== undefined) return payload.answer;

  return answer;
}

function normalizeStringToken(value: unknown): string {
  if (typeof value === "string") return value.trim().toLowerCase();
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value).trim().toLowerCase();
  }
  return "";
}

function normalizeChoiceToken(value: unknown, optionsRaw: unknown): string {
  const token = normalizeStringToken(value);
  if (!token) return "";

  const options = parseQuizOptions(optionsRaw);
  if (options.length === 0) return token;

  const byId = options.find((option) => option.id.trim().toLowerCase() === token);
  if (byId) return byId.id;

  const byText = options.find((option) => option.text.trim().toLowerCase() === token);
  if (byText) return byText.id;

  return token;
}

function normalizeStringArray(value: unknown): string[] {
  const extracted = extractAnswerValue(value);

  if (Array.isArray(extracted)) {
    return extracted
      .map((item) => normalizeStringToken(item))
      .filter((item) => item.length > 0);
  }

  const token = normalizeStringToken(extracted);
  return token ? [token] : [];
}

function normalizeBoolean(value: unknown): boolean | null {
  const extracted = extractAnswerValue(value);
  if (typeof extracted === "boolean") return extracted;
  if (typeof extracted === "number") return extracted !== 0;
  if (typeof extracted === "string") {
    const normalized = extracted.trim().toLowerCase();
    if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
    if (normalized === "false" || normalized === "0" || normalized === "no") return false;
  }
  return null;
}

function normalizeNumber(value: unknown): number | null {
  const extracted = extractAnswerValue(value);
  if (typeof extracted === "number" && Number.isFinite(extracted)) return extracted;
  if (typeof extracted === "string") {
    const parsed = Number(extracted.trim());
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function normalizePairs(value: unknown): Array<{ left: string; right: string }> {
  const extracted = extractAnswerValue(value);

  if (Array.isArray(extracted)) {
    return extracted
      .map((entry) => {
        if (!entry || typeof entry !== "object") return null;
        const pair = entry as Record<string, unknown>;
        const left = normalizeStringToken(pair.left);
        const right = normalizeStringToken(pair.right);
        if (!left || !right) return null;
        return { left, right };
      })
      .filter((pair): pair is { left: string; right: string } => pair !== null)
      .sort((a, b) =>
        a.left === b.left ? a.right.localeCompare(b.right) : a.left.localeCompare(b.left)
      );
  }

  if (extracted && typeof extracted === "object") {
    const entries = Object.entries(extracted as Record<string, unknown>)
      .map(([left, right]) => ({
        left: normalizeStringToken(left),
        right: normalizeStringToken(right),
      }))
      .filter((pair) => pair.left.length > 0 && pair.right.length > 0)
      .sort((a, b) =>
        a.left === b.left ? a.right.localeCompare(b.right) : a.left.localeCompare(b.left)
      );
    return entries;
  }

  return [];
}

function arraysEqualOrdered(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((value, index) => value === b[index]);
}

function arraysEqualAsSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return arraysEqualOrdered(sortedA, sortedB);
}

function toComparable(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") return value.trim().toLowerCase();
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map((entry) => toComparable(entry));
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const normalized: Record<string, unknown> = {};
    for (const key of keys) normalized[key] = toComparable(record[key]);
    return normalized;
  }
  return String(value).trim().toLowerCase();
}

function serializeQuizAnswer(value: unknown): string {
  const extracted = extractAnswerValue(value);
  if (extracted === null || extracted === undefined) return "";
  if (typeof extracted === "string") return extracted;
  if (typeof extracted === "number" || typeof extracted === "boolean") {
    return String(extracted);
  }
  try {
    return JSON.stringify(extracted);
  } catch {
    return String(extracted);
  }
}

type QuizQuestionForAnswerCheck = {
  type: string;
  correctAnswer: string | null;
  options: unknown;
};

export function isQuizAnswerCorrect(
  question: QuizQuestionForAnswerCheck,
  providedAnswer: unknown
): boolean {
  const expected = parseJsonIfNeeded(question.correctAnswer);
  const actual = extractAnswerValue(providedAnswer);

  if (expected === null || expected === undefined || expected === "") {
    return false;
  }

  switch (question.type) {
    case "multiple_choice": {
      const expectedChoice = normalizeChoiceToken(expected, question.options);
      const actualChoice = normalizeChoiceToken(actual, question.options);
      return expectedChoice.length > 0 && expectedChoice === actualChoice;
    }
    case "true_false": {
      const expectedBool = normalizeBoolean(expected);
      const actualBool = normalizeBoolean(actual);
      return expectedBool !== null && actualBool !== null && expectedBool === actualBool;
    }
    case "numeric": {
      const expectedNumber = normalizeNumber(expected);
      const actualNumber = normalizeNumber(actual);
      return expectedNumber !== null && actualNumber !== null && expectedNumber === actualNumber;
    }
    case "multi_select": {
      const expectedValues = normalizeStringArray(expected).map((value) =>
        normalizeChoiceToken(value, question.options)
      );
      const actualValues = normalizeStringArray(actual).map((value) =>
        normalizeChoiceToken(value, question.options)
      );
      return arraysEqualAsSet(
        expectedValues.filter((value) => value.length > 0),
        actualValues.filter((value) => value.length > 0)
      );
    }
    case "ordering": {
      return arraysEqualOrdered(normalizeStringArray(expected), normalizeStringArray(actual));
    }
    case "fill_in_blank": {
      return arraysEqualOrdered(normalizeStringArray(expected), normalizeStringArray(actual));
    }
    case "matching": {
      const expectedPairs = normalizePairs(expected);
      const actualPairs = normalizePairs(actual);
      return JSON.stringify(expectedPairs) === JSON.stringify(actualPairs);
    }
    default: {
      return (
        JSON.stringify(toComparable(extractAnswerValue(expected))) ===
        JSON.stringify(toComparable(actual))
      );
    }
  }
}

export async function listQuizzes(moduleId?: number) {
  if (moduleId) {
    return db
      .select()
      .from(quizzes)
      .where(eq(quizzes.moduleId, moduleId))
      .orderBy(quizzes.createdAt);
  }
  return db.select().from(quizzes).orderBy(quizzes.createdAt);
}

export async function getQuizById(id: number) {
  const [quiz] = await db.select().from(quizzes).where(eq(quizzes.id, id));
  return quiz ?? null;
}

export async function listQuizQuestions(quizId: number) {
  return db
    .select({
      id: quizQuestions.id,
      quizId: quizQuestions.quizId,
      type: quizQuestions.type,
      questionText: quizQuestions.questionText,
      options: quizQuestions.options,
      points: quizQuestions.points,
    })
    .from(quizQuestions)
    .where(eq(quizQuestions.quizId, quizId));
}

export async function listQuizQuestionsForReview(quizId: number) {
  return db
    .select({
      id: quizQuestions.id,
      quizId: quizQuestions.quizId,
      type: quizQuestions.type,
      questionText: quizQuestions.questionText,
      options: quizQuestions.options,
      correctAnswer: quizQuestions.correctAnswer,
      explanation: quizQuestions.explanation,
      points: quizQuestions.points,
    })
    .from(quizQuestions)
    .where(eq(quizQuestions.quizId, quizId));
}

export async function updateQuizReview(
  quizId: number,
  input: QuizReviewUpdateInput
) {
  const existingQuiz = await getQuizById(quizId);
  if (!existingQuiz) {
    throw new HttpError("Quiz not found", 404);
  }

  const quizUpdateData: Record<string, unknown> = {};

  if (input.title !== undefined) {
    const nextTitle = input.title.trim();
    if (!nextTitle) {
      throw new HttpError("Quiz title cannot be empty", 400);
    }
    quizUpdateData.title = nextTitle;
  }
  if (input.description !== undefined) {
    quizUpdateData.description = toNullableText(input.description);
  }
  if (input.difficulty !== undefined) {
    quizUpdateData.difficulty = input.difficulty;
  }
  if (input.source !== undefined) {
    const normalizedSource = input.source.trim().toLowerCase();
    if (!normalizedSource) {
      throw new HttpError("Quiz source cannot be empty", 400);
    }
    quizUpdateData.source = normalizedSource;
  }
  if (input.capsTags !== undefined) {
    quizUpdateData.capsTags = input.capsTags;
  }
  if (input.revealCorrectAnswers !== undefined) {
    quizUpdateData.revealCorrectAnswers = input.revealCorrectAnswers;
  }
  if (input.revealToParents !== undefined) {
    quizUpdateData.revealToParents = input.revealToParents;
  }

  if (Object.keys(quizUpdateData).length === 0 && !input.questions?.length) {
    throw new HttpError("No quiz changes provided", 400);
  }

  let updatedQuiz = existingQuiz;
  if (Object.keys(quizUpdateData).length > 0) {
    const [row] = await db
      .update(quizzes)
      .set(quizUpdateData as any)
      .where(eq(quizzes.id, quizId))
      .returning();
    if (row) {
      updatedQuiz = row;
    }
  }

  if (input.questions?.length) {
    const existingQuestions = await db
      .select({ id: quizQuestions.id })
      .from(quizQuestions)
      .where(eq(quizQuestions.quizId, quizId));

    const existingQuestionIds = new Set(existingQuestions.map((q) => q.id));
    const invalidQuestionIds = input.questions
      .map((q) => q.id)
      .filter((id) => !existingQuestionIds.has(id));

    if (invalidQuestionIds.length > 0) {
      throw new HttpError(
        `Unknown question id(s) for this quiz: ${invalidQuestionIds.join(", ")}`,
        400
      );
    }

    for (const question of input.questions) {
      const normalizedQuestionText = question.questionText.trim();
      if (!normalizedQuestionText) {
        throw new HttpError(`Question ${question.id} text cannot be empty`, 400);
      }

      const questionUpdateData: Record<string, unknown> = {
        type: question.type,
        questionText: normalizedQuestionText,
      };
      if (question.options !== undefined) {
        questionUpdateData.options = question.options ?? null;
      }
      if (question.correctAnswer !== undefined) {
        questionUpdateData.correctAnswer = toNullableText(question.correctAnswer);
      }
      if (question.explanation !== undefined) {
        questionUpdateData.explanation = toNullableText(question.explanation);
      }
      if (question.points !== undefined) {
        questionUpdateData.points = question.points;
      }

      await db
        .update(quizQuestions)
        .set(questionUpdateData as any)
        .where(and(eq(quizQuestions.id, question.id), eq(quizQuestions.quizId, quizId)));
    }
  }

  const questions = await listQuizQuestionsForReview(quizId);

  return {
    quiz: updatedQuiz,
    questions,
  };
}

export async function generateQuiz(input: QuizGenerateInput, userId: string) {
  const limiter = rateLimit(`quiz-gen:${userId}`, { windowMs: 60_000, max: 5 });
  if (!limiter.allowed) {
    throw new HttpError("Rate limit exceeded", 429);
  }

  const [subject] = await db.select().from(subjects).where(eq(subjects.id, input.subjectId));

  let difficulty = input.difficulty;
  if (difficulty === "adaptive") {
    const [profile] = await db
      .select({ recommendedDifficulty: learningProfiles.recommendedDifficulty })
      .from(learningProfiles)
      .where(eq(learningProfiles.userId, userId));
    difficulty = profile?.recommendedDifficulty ?? "medium";
  }

  const prompt = quizPromptTemplate({
    grade: input.grade,
    subject: subject?.name ?? "Subject",
    topic: input.topic,
    capsTags: input.capsTags,
    difficulty,
  });

  const client = await getOpenAiClient();
  const completion = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }],
    response_format: { type: "json_object" },
  });

  const content = completion.choices[0]?.message?.content ?? "{}";
  let parsedQuiz: { title?: string; description?: string; questions?: any[] } = {};
  try {
    parsedQuiz = JSON.parse(content);
  } catch {
    parsedQuiz = {};
  }

  const rawQuestions = Array.isArray(parsedQuiz.questions) ? parsedQuiz.questions : [];
  const normalizedQuestions = rawQuestions
    .filter((entry): entry is Record<string, unknown> => !!entry && typeof entry === "object")
    .map((question, index) => normalizeGeneratedQuizQuestion(question, index));

  if (normalizedQuestions.length === 0) {
    throw new HttpError("Quiz generation failed. Please try again.", 502);
  }

  const questions = ensureMinimumGeneratedQuestions(
    normalizedQuestions,
    MIN_QUIZ_QUESTION_COUNT
  );

  const [quiz] = await db
    .insert(quizzes)
    .values({
      moduleId: input.moduleId,
      title: parsedQuiz.title ?? input.topic,
      description: parsedQuiz.description ?? "AI generated quiz",
      difficulty,
      source: "ai",
      capsTags: input.capsTags,
      createdBy: userId,
    })
    .returning();

  await db.insert(quizQuestions).values(
    questions.map((question) => ({
      quizId: quiz.id,
      type: question.type as any,
      questionText: question.questionText,
      options: question.options as any,
      correctAnswer: question.correctAnswer,
      explanation: question.explanation,
      points: question.points,
    }))
  );

  return { quizId: quiz.id, questionCount: questions.length };
}

export async function submitQuiz(input: QuizSubmitInput, userId: string) {
  const questions = await db
    .select()
    .from(quizQuestions)
    .where(eq(quizQuestions.quizId, input.quizId));

  if (questions.length === 0) {
    throw new HttpError("Quiz has no questions", 400);
  }

  let score = 0;
  const answersToStore = input.answers.map((answer) => {
    const question = questions.find((item) => item.id === answer.questionId);
    if (!question) {
      throw new HttpError(`Question ${answer.questionId} does not belong to this quiz`, 400);
    }

    const isCorrect = isQuizAnswerCorrect(
      {
        type: question.type,
        correctAnswer: question.correctAnswer ?? null,
        options: question.options,
      },
      answer.answer
    );
    const points = isCorrect ? question?.points ?? 1 : 0;
    score += points;
    return {
      questionId: answer.questionId,
      answer: serializeQuizAnswer(answer.answer),
      isCorrect,
      score: points,
    };
  });

  const maxScore = questions.reduce((total, question) => total + (question.points ?? 1), 0);
  const percentage = maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;
  const recommendedDifficulty =
    percentage >= 85 ? "hard" : percentage >= 65 ? "medium" : "easy";

  const feedback =
    score >= maxScore * 0.8
      ? "Excellent work!"
      : score >= maxScore * 0.5
      ? "Good effort. Review the tricky questions."
      : "Keep practicing. Review the lesson materials.";

  const [attempt] = await db
    .insert(quizAttempts)
    .values({
      quizId: input.quizId,
      userId,
      score,
      maxScore,
      feedback,
    })
    .returning();

  if (answersToStore.length > 0) {
    await db.insert(quizAnswers).values(
      answersToStore.map((answer) => ({
        attemptId: attempt.id,
        questionId: answer.questionId,
        answer: answer.answer,
        isCorrect: answer.isCorrect,
        score: answer.score,
      }))
    );
  }

  const [existingProfile] = await db
    .select()
    .from(learningProfiles)
    .where(eq(learningProfiles.userId, userId));

  if (existingProfile) {
    await db
      .update(learningProfiles)
      .set({
        recommendedDifficulty,
        lastAdaptiveUpdateAt: new Date(),
        updatedAt: new Date(),
      })
      .where(eq(learningProfiles.userId, userId));
  } else {
    await db.insert(learningProfiles).values({
      userId,
      recommendedDifficulty,
      lastAdaptiveUpdateAt: new Date(),
      updatedAt: new Date(),
    });
  }

  const masteryBadges = await db
    .select()
    .from(badges)
    .where(eq(badges.ruleKey, "quiz_mastery"));

  if (masteryBadges.length > 0) {
    const attempts = await db
      .select({ score: quizAttempts.score, maxScore: quizAttempts.maxScore })
      .from(quizAttempts)
      .where(eq(quizAttempts.userId, userId));

    for (const badge of masteryBadges) {
      const criteria = badge.criteria as { score?: number; count?: number };
      const requiredScore = criteria.score ?? 80;
      const requiredCount = criteria.count ?? 3;

      const qualifying = attempts.filter((entry) => {
        const percentage = Math.round((entry.score / entry.maxScore) * 100);
        return percentage >= requiredScore;
      });

      if (qualifying.length >= requiredCount) {
        const [existingBadge] = await db
          .select()
          .from(userBadges)
          .where(and(eq(userBadges.userId, userId), eq(userBadges.badgeId, badge.id)));

        if (!existingBadge) {
          await db.insert(userBadges).values({
            userId,
            badgeId: badge.id,
            awardedAt: new Date(),
          });
        }
      }
    }
  }

  return {
    attemptId: attempt.id,
    score,
    maxScore,
    feedback,
    recommendedDifficulty,
  };
}
