import "dotenv/config";
import { eq, sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import {
  questionBankItems,
  quizQuestions,
  quizzes,
} from "../core/database/schema/index.js";

const MIN_QUIZ_QUESTION_COUNT = 20;

type QuestionTemplate = {
  type: string;
  questionText: string;
  options: unknown;
  correctAnswer: string | null;
  explanation: string | null;
  points: number;
  difficulty: string | null;
  topicId: number | null;
  tags: unknown;
  imageUrl: string | null;
  timeLimitSeconds: number | null;
  questionBankItemId: number | null;
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

function toTemplateFromExistingQuestion(
  question: Awaited<ReturnType<typeof getQuizQuestions>>[number]
): QuestionTemplate {
  return {
    type: question.type,
    questionText: question.questionText,
    options: question.options ?? null,
    correctAnswer: question.correctAnswer ?? null,
    explanation: question.explanation ?? null,
    points: question.points ?? 1,
    difficulty: question.difficulty ?? "medium",
    topicId: question.topicId ?? null,
    tags: question.tags ?? [],
    imageUrl: question.imageUrl ?? null,
    timeLimitSeconds: question.timeLimitSeconds ?? null,
    questionBankItemId: question.questionBankItemId ?? null,
  };
}

function toTemplateFromQuestionBank(
  item: Awaited<ReturnType<typeof getModuleQuestionBank>>[number]
): QuestionTemplate {
  return {
    type: item.type,
    questionText: item.questionText,
    options: item.options ?? null,
    correctAnswer: toNullableText(item.correctAnswer),
    explanation: item.explanation ?? null,
    points: item.points ?? 1,
    difficulty: item.difficulty ?? "medium",
    topicId: item.topicId ?? null,
    tags: item.tags ?? [],
    imageUrl: item.imageUrl ?? null,
    timeLimitSeconds: item.timeLimitSeconds ?? null,
    questionBankItemId: item.id,
  };
}

function toInsertRow(quizId: number, question: QuestionTemplate) {
  return {
    quizId,
    type: question.type as any,
    questionText: question.questionText,
    options: question.options as any,
    correctAnswer: question.correctAnswer,
    explanation: question.explanation,
    points: question.points,
    difficulty: question.difficulty as any,
    topicId: question.topicId,
    questionBankItemId: question.questionBankItemId,
    tags: question.tags as any,
    imageUrl: question.imageUrl,
    timeLimitSeconds: question.timeLimitSeconds,
  };
}

async function getQuizQuestions(quizId: number) {
  return db
    .select()
    .from(quizQuestions)
    .where(eq(quizQuestions.quizId, quizId))
    .orderBy(quizQuestions.id);
}

async function getModuleQuestionBank(moduleId: number) {
  return db
    .select({
      id: questionBankItems.id,
      type: questionBankItems.type,
      questionText: questionBankItems.questionText,
      options: questionBankItems.options,
      correctAnswer: questionBankItems.correctAnswer,
      explanation: questionBankItems.explanation,
      points: questionBankItems.points,
      difficulty: questionBankItems.difficulty,
      topicId: questionBankItems.topicId,
      tags: questionBankItems.tags,
      imageUrl: questionBankItems.imageUrl,
      timeLimitSeconds: questionBankItems.timeLimitSeconds,
    })
    .from(questionBankItems)
    .where(eq(questionBankItems.moduleId, moduleId))
    .orderBy(questionBankItems.id);
}

async function fixQuizQuestionCounts() {
  const quizRows = await db
    .select({
      id: quizzes.id,
      moduleId: quizzes.moduleId,
      title: quizzes.title,
    })
    .from(quizzes)
    .orderBy(quizzes.id);

  let updatedQuizzes = 0;
  let totalInserted = 0;
  let skippedQuizzes = 0;

  for (const quiz of quizRows) {
    const existingQuestions = await getQuizQuestions(quiz.id);
    if (existingQuestions.length >= MIN_QUIZ_QUESTION_COUNT) {
      continue;
    }

    const needed = MIN_QUIZ_QUESTION_COUNT - existingQuestions.length;
    const inserts: ReturnType<typeof toInsertRow>[] = [];
    const existingTemplates = existingQuestions.map((question) =>
      toTemplateFromExistingQuestion(question)
    );

    const existingBankIds = new Set(
      existingQuestions
        .map((question) => question.questionBankItemId)
        .filter((id): id is number => typeof id === "number")
    );

    const moduleBank = await getModuleQuestionBank(quiz.moduleId);
    const unusedBankTemplates = moduleBank
      .filter((item) => !existingBankIds.has(item.id))
      .map((item) => toTemplateFromQuestionBank(item));

    for (const template of unusedBankTemplates) {
      if (inserts.length >= needed) break;
      inserts.push(toInsertRow(quiz.id, template));
    }

    const remaining = needed - inserts.length;
    if (remaining > 0) {
      const clonePool =
        existingTemplates.length > 0 ? existingTemplates : unusedBankTemplates;
      if (clonePool.length === 0) {
        console.warn(
          `[fix-quiz-question-count] Skipped quiz ${quiz.id} (${quiz.title}) - no source questions available`
        );
        skippedQuizzes += 1;
        continue;
      }

      for (let index = 0; index < remaining; index += 1) {
        const source = clonePool[index % clonePool.length];
        const sequence = existingQuestions.length + inserts.length + 1;
        const baseText =
          source.questionText.trim().length > 0
            ? source.questionText
            : `Practice question ${sequence}`;
        inserts.push(
          toInsertRow(quiz.id, {
            ...source,
            questionText: `${baseText} (Practice ${sequence})`,
            questionBankItemId: null,
          })
        );
      }
    }

    if (inserts.length > 0) {
      await db.insert(quizQuestions).values(inserts as any);
      updatedQuizzes += 1;
      totalInserted += inserts.length;
      console.log(
        `[fix-quiz-question-count] Quiz ${quiz.id} (${quiz.title}) -> +${inserts.length} questions`
      );
    }
  }

  const remainingUnderMin = await db.execute(sql.raw(`
    SELECT COUNT(*)
    FROM (
      SELECT q.id
      FROM quizzes q
      LEFT JOIN quiz_questions qq ON qq.quiz_id = q.id
      GROUP BY q.id
      HAVING COUNT(qq.id) < ${MIN_QUIZ_QUESTION_COUNT}
    ) t
  `));

  const underMinCount = Number((remainingUnderMin.rows?.[0] as any)?.count ?? 0);

  console.log(
    `[fix-quiz-question-count] Done. updatedQuizzes=${updatedQuizzes}, inserted=${totalInserted}, skipped=${skippedQuizzes}, underMin=${underMinCount}`
  );
}

fixQuizQuestionCounts().catch((error) => {
  console.error("[fix-quiz-question-count] Failed", error);
  process.exit(1);
});
