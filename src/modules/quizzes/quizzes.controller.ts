import type { Request, Response } from "express";
import { asyncHandler } from "../../core/middleware/async-handler.js";
import { parseNumber } from "../../shared/utils/parse.js";
import {
  generateQuiz,
  getQuizById,
  isQuizAnswerCorrect,
  listQuizQuestions,
  listQuizQuestionsForReview,
  listQuizzes,
  submitQuiz,
  updateQuizReview,
} from "./quizzes.service.js";
import {
  quizCheckSchema,
  quizQuerySchema,
  quizUpdateSchema,
} from "../../shared/validators/index.js";
import { db } from "../../core/database/index.js";
import { quizQuestions } from "../../core/database/schema/index.js";
import { eq, and } from "drizzle-orm";

function toPercentage(score: number, maxScore: number) {
  if (!Number.isFinite(maxScore) || maxScore <= 0) return 0;
  return Math.round((score / maxScore) * 100);
}

type QuestionOption = {
  id: string;
  text: string;
};

function parseJsonString(value: string): unknown {
  const trimmed = value.trim();
  if (!trimmed) return value;
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return value;
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function extractAnswerValue(value: unknown): unknown {
  if (typeof value === "string") {
    const parsed = parseJsonString(value);
    if (parsed !== value) return extractAnswerValue(parsed);
  }

  if (!value || typeof value !== "object" || Array.isArray(value)) return value;

  const payload = value as Record<string, unknown>;
  if (payload.value !== undefined) return extractAnswerValue(payload.value);
  if (payload.answer !== undefined) return extractAnswerValue(payload.answer);
  if (payload.correctAnswer !== undefined) return extractAnswerValue(payload.correctAnswer);
  return value;
}

function toDisplayText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    return value.map((entry) => toDisplayText(entry)).filter(Boolean).join(", ");
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > 0) {
      return entries
        .map(([left, right]) => `${left} -> ${toDisplayText(right)}`)
        .join(", ");
    }
  }
  return String(value);
}

function parseOptions(raw: unknown): QuestionOption[] {
  if (!Array.isArray(raw)) return [];

  return raw.map((entry, index) => {
    if (typeof entry === "string") return { id: String(index), text: entry };
    if (entry && typeof entry === "object") {
      const option = entry as Record<string, unknown>;
      return {
        id: String(option.id ?? index),
        text: toDisplayText(option.text ?? option.label ?? option.value) || `Option ${index + 1}`,
      };
    }
    return {
      id: String(index),
      text: toDisplayText(entry) || `Option ${index + 1}`,
    };
  });
}

function optionLabel(value: unknown, optionsRaw: unknown): string {
  const token = toDisplayText(value).trim();
  if (!token) return "";

  const tokenLower = token.toLowerCase();
  const options = parseOptions(optionsRaw);
  const byId = options.find((option) => option.id.trim().toLowerCase() === tokenLower);
  if (byId) return byId.text;
  const byText = options.find((option) => option.text.trim().toLowerCase() === tokenLower);
  if (byText) return byText.text;
  return token;
}

function formatAnswer(value: unknown, optionsRaw: unknown): string {
  const extracted = extractAnswerValue(value);
  if (extracted === null || extracted === undefined) return "-";

  if (Array.isArray(extracted)) {
    const labels = extracted
      .map((entry) => optionLabel(entry, optionsRaw))
      .filter((entry) => entry.trim().length > 0);
    return labels.length > 0 ? labels.join(", ") : "-";
  }

  if (typeof extracted === "object") {
    const entries = Object.entries(extracted as Record<string, unknown>);
    if (entries.length > 0) {
      return entries
        .map(([left, right]) => `${left} -> ${optionLabel(right, optionsRaw)}`)
        .join(", ");
    }
  }

  return optionLabel(extracted, optionsRaw) || "-";
}

export const list = asyncHandler(async (req: Request, res: Response) => {
  const parsed = quizQuerySchema.safeParse({
    moduleId: req.query.moduleId ? Number(req.query.moduleId) : undefined,
  });
  if (!parsed.success) {
    res.status(400).json({ message: "Invalid query", issues: parsed.error.issues });
    return;
  }
  const data = await listQuizzes(parsed.data.moduleId);
  res.json(data);
});

export const getById = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid quiz id" });
    return;
  }
  const quiz = await getQuizById(id);
  if (!quiz) {
    res.status(404).json({ message: "Quiz not found" });
    return;
  }
  const questions = await listQuizQuestions(id);
  res.json({ quiz, questions });
});

export const getReviewById = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid quiz id" });
    return;
  }

  const quiz = await getQuizById(id);
  if (!quiz) {
    res.status(404).json({ message: "Quiz not found" });
    return;
  }

  const questions = await listQuizQuestionsForReview(id);
  res.json({ quiz, questions });
});

export const listQuestions = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid quiz id" });
    return;
  }
  const questions = await listQuizQuestions(id);
  res.json(questions);
});

export const generate = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  const result = await generateQuiz(req.body, userId);
  res.json(result);
});

export const update = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid quiz id" });
    return;
  }

  const parsed = quizUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ message: "Invalid payload", issues: parsed.error.issues });
    return;
  }

  const result = await updateQuizReview(id, parsed.data);
  res.json(result);
});

export const submit = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  const result = await submitQuiz(req.body, userId);
  res.json(result);
});

export const check = asyncHandler(async (req: Request, res: Response) => {
  const parsed = quizCheckSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ message: "Invalid payload", issues: parsed.error.issues });
    return;
  }

  const [question] = await db
    .select()
    .from(quizQuestions)
    .where(eq(quizQuestions.id, parsed.data.questionId));

  if (!question) {
    res.status(404).json({ message: "Question not found" });
    return;
  }

  const isCorrect = isQuizAnswerCorrect(
    {
      type: question.type,
      correctAnswer: question.correctAnswer ?? null,
      options: question.options,
    },
    parsed.data.answer
  );

  const explanation = question.explanation ?? "";
  const hint = explanation
    ? `${explanation.split(".")[0].trim()}${explanation.includes(".") ? "." : ""}`
    : "Review the lesson notes and try a different approach.";

  res.json({
    questionId: question.id,
    isCorrect,
    hint,
    explanation: isCorrect ? explanation : null,
  });
});

// ============ RBAC-ENABLED QUIZ ENDPOINTS ============

/**
 * GET /api/quizzes/:quizId/attempts
 * Get all attempts for a quiz (with RBAC and answer visibility)
 * Role: STUDENT (self), PARENT (linked), TUTOR, ADMIN
 */
export const getQuizAttempts = asyncHandler(async (req: Request, res: Response) => {
  const quizId = parseNumber(req.params.quizId as string);
  const studentId = req.query.studentId as string | undefined;

  if (!quizId) {
    res.status(400).json({ message: "Invalid quiz id" });
    return;
  }

  if (!req.user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const userId = studentId ? String(studentId) : req.user.id;

  // Check if user has access (handled by guard middleware in routes)
  const { quizAttempts } = await import("../../core/database/schema/index.js");
  const { getAccessibleStudentIds } = await import("../../shared/rbac/guard.js");

  const accessibleIds = await getAccessibleStudentIds(req.user.id, req.user.role);
  if (!accessibleIds.includes(userId)) {
    res.status(403).json({ message: "Access denied" });
    return;
  }

  // Get quiz to check visibility settings
  const quiz = await getQuizById(quizId);
  if (!quiz) {
    res.status(404).json({ message: "Quiz not found" });
    return;
  }

  // Get all attempts
  const attempts = await db.query.quizAttempts.findMany({
    where: and(
      eq(quizAttempts.quizId, quizId),
      eq(quizAttempts.userId, userId)
    ),
    with: {
      answers: {
        with: {
          question: true,
        },
      },
    },
    orderBy: (attempts, { desc }) => [desc(attempts.createdAt)],
  });

  // Determine if correct answers should be revealed
  const isParent = req.user.role === "PARENT" && accessibleIds.includes(userId);
  const showCorrectAnswers =
    quiz.revealCorrectAnswers ||
    (isParent && quiz.revealToParents) ||
    req.user.role === "TUTOR" ||
    req.user.role === "ADMIN";

  // Return attempts with conditional answer visibility
  res.json({
    quiz: {
      id: quiz.id,
      title: quiz.title,
      difficulty: quiz.difficulty,
      revealCorrectAnswers: quiz.revealCorrectAnswers,
      revealToParents: quiz.revealToParents,
    },
    attempts: attempts.map((attempt) => ({
      id: attempt.id,
      score: attempt.score,
      maxScore: attempt.maxScore,
      percentage: toPercentage(attempt.score, attempt.maxScore),
      createdAt: attempt.createdAt,
      answers: showCorrectAnswers
        ? ((attempt as any).answers ?? []).map((answer: any) => ({
            questionId: answer.questionId,
            questionText: answer.question?.questionText ?? undefined,
            selectedAnswer: formatAnswer(answer.answer, answer.question?.options),
            correctAnswer: answer.question?.correctAnswer
              ? formatAnswer(answer.question.correctAnswer, answer.question?.options)
              : undefined,
            isCorrect: answer.isCorrect,
          }))
        : undefined,
    })),
    showCorrectAnswers,
  });
});

/**
 * GET /api/students/:studentId/quiz-results
 * Get all quiz results for a student (parent access)
 * Role: PARENT (linked), TUTOR, ADMIN
 */
export const getStudentQuizResults = asyncHandler(async (req: Request, res: Response) => {
  const studentId = req.params.studentId as string;

  if (!req.user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const { quizAttempts } = await import("../../core/database/schema/index.js");
  const { getAccessibleStudentIds } = await import("../../shared/rbac/guard.js");

  // Check access
  const accessibleIds = await getAccessibleStudentIds(req.user.id, req.user.role);
  if (!accessibleIds.includes(studentId)) {
    res.status(403).json({ message: "Access denied" });
    return;
  }

  // Get all quiz attempts for student
  const attempts = await db.query.quizAttempts.findMany({
    where: eq(quizAttempts.userId, studentId),
    with: {
      quiz: {
        with: {
          module: true,
        },
      },
      answers: {
        with: {
          question: true,
        },
      },
    },
    orderBy: (attempts, { desc }) => [desc(attempts.createdAt)],
  });

  // Group by quiz and determine visibility
  const currentUser = req.user!;
  const isParent = currentUser.role === "PARENT";
  const results = attempts.map((attempt) => {
    const showCorrectAnswers =
      attempt.quiz.revealCorrectAnswers ||
      (isParent && attempt.quiz.revealToParents) ||
      currentUser.role === "TUTOR" ||
      currentUser.role === "ADMIN";

    return {
      attemptId: attempt.id,
      quizId: attempt.quiz.id,
      quizTitle: attempt.quiz.title,
      moduleName: attempt.quiz.module.title,
      moduleId: attempt.quiz.moduleId,
      difficulty: attempt.quiz.difficulty,
      score: attempt.score,
      maxScore: attempt.maxScore,
      percentage: toPercentage(attempt.score, attempt.maxScore),
      createdAt: attempt.createdAt,
      showCorrectAnswers,
      answers: showCorrectAnswers
        ? ((attempt as any).answers ?? []).map((answer: any) => ({
            questionId: answer.questionId,
            questionText: answer.question?.questionText ?? undefined,
            selectedAnswer: formatAnswer(answer.answer, answer.question?.options),
            correctAnswer: answer.question?.correctAnswer
              ? formatAnswer(answer.question.correctAnswer, answer.question?.options)
              : undefined,
            isCorrect: answer.isCorrect,
          }))
        : undefined,
    };
  });

  res.json({
    studentId,
    totalAttempts: results.length,
    averageScore:
      results.length > 0
        ? Math.round(
            results.reduce((sum, r) => sum + r.percentage, 0) / results.length
          )
        : 0,
    results,
  });
});

/**
 * PATCH /api/quizzes/:quizId/visibility
 * Update quiz answer visibility settings
 * Role: TUTOR, ADMIN
 */
export const updateQuizVisibility = asyncHandler(async (req: Request, res: Response) => {
  const quizId = parseNumber(req.params.quizId as string);
  const { revealCorrectAnswers, revealToParents } = req.body;

  if (!quizId) {
    res.status(400).json({ message: "Invalid quiz id" });
    return;
  }

  if (!req.user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  // Check if quiz exists
  const quiz = await getQuizById(quizId);
  if (!quiz) {
    res.status(404).json({ message: "Quiz not found" });
    return;
  }

  // Update visibility settings
  const { quizzes } = await import("../../core/database/schema/index.js");
  const updateData: any = {};

  if (revealCorrectAnswers !== undefined) {
    updateData.revealCorrectAnswers = revealCorrectAnswers;
  }
  if (revealToParents !== undefined) {
    updateData.revealToParents = revealToParents;
  }

  if (Object.keys(updateData).length === 0) {
    res.status(400).json({ message: "No visibility settings to update" });
    return;
  }

  const [updated] = await db
    .update(quizzes)
    .set(updateData)
    .where(eq(quizzes.id, quizId))
    .returning();

  // Log audit
  const { logAudit } = await import("../../shared/audit/audit-log.js");
  await logAudit({
    actorId: req.user.id,
    action: "quiz.visibility_update",
    entity: "quiz",
    entityId: quizId,
    details: updateData,
    req,
  });

  res.json({
    message: "Quiz visibility updated",
    quiz: {
      id: updated.id,
      title: updated.title,
      revealCorrectAnswers: updated.revealCorrectAnswers,
      revealToParents: updated.revealToParents,
    },
  });
});
