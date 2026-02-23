import { and, count, eq, inArray, isNull, or, sql } from "drizzle-orm";
import { randomUUID } from "crypto";
import { db } from "../../core/database/index.js";
import {
  assessments,
  assessmentSections,
  assessmentQuestions,
  assessmentAttempts,
  attemptAnswers,
  paperAssignments,
  questionBankItems,
  users,
} from "../../core/database/schema/index.js";
import { HttpError } from "../../shared/utils/http-error.js";

// ── Types ────────────────────────────────────────────────────────────────────

export type PaperStatus = "draft" | "published" | "closed" | "marking" | "released" | "archived";

type CreatePaperInput = {
  title: string;
  subjectId: number;
  grade?: number;
  totalMarks?: number;
  timeLimitMinutes?: number;
  instructions?: string;
  strictMode?: boolean;
  paperType?: string;
};

type UpdatePaperInput = Partial<CreatePaperInput>;

type CreateSectionInput = {
  label?: string;
  title?: string;
  instructions?: string;
  totalMarks?: number;
  order: number;
  strictMode?: boolean;
};

type AddQuestionInput = {
  questionBankItemId: number;
  overridePoints?: number;
  order: number;
};

type AssignPaperInput = {
  studentIds: string[];
  openAt?: string;
  closeAt?: string;
  maxAttempts?: number;
};

type MarkAnswerInput = {
  score: number;
  markerComment?: string;
};

// ── Helpers ──────────────────────────────────────────────────────────────────

async function getPaperOrThrow(id: number) {
  const [paper] = await db
    .select()
    .from(assessments)
    .where(and(eq(assessments.id, id), eq(assessments.isManualPaper, true)));
  if (!paper) throw new HttpError("Paper not found", 404);
  return paper;
}

// ── Service functions ────────────────────────────────────────────────────────

export async function listPapers(opts: {
  role: string;
  subjectId?: number;
  status?: string;
  limit?: number;
  offset?: number;
}) {
  const conditions = [eq(assessments.isManualPaper, true)];
  if (opts.subjectId) conditions.push(eq(assessments.subjectId, opts.subjectId));
  if (opts.status) conditions.push(eq(assessments.status, opts.status as PaperStatus));

  const rows = await db
    .select()
    .from(assessments)
    .where(and(...conditions))
    .orderBy(sql`${assessments.createdAt} desc`)
    .limit(opts.limit ?? 50)
    .offset(opts.offset ?? 0);

  return rows;
}

export async function createPaper(input: CreatePaperInput, createdBy: string) {
  const [paper] = await db
    .insert(assessments)
    .values({
      title: input.title,
      type: "test",
      status: "draft",
      subjectId: input.subjectId,
      grade: input.grade,
      totalMarks: input.totalMarks,
      timeLimitMinutes: input.timeLimitMinutes,
      instructions: input.instructions,
      strictMode: input.strictMode ?? false,
      paperType: input.paperType ?? "weekly",
      isManualPaper: true,
      createdBy,
    })
    .returning();
  return paper;
}

export async function getPaper(id: number) {
  const paper = await getPaperOrThrow(id);

  const sections = await db
    .select()
    .from(assessmentSections)
    .where(eq(assessmentSections.assessmentId, id))
    .orderBy(assessmentSections.order);

  const sectionIds = sections.map((s) => s.id);
  const questions =
    sectionIds.length > 0
      ? await db
          .select({
            id: assessmentQuestions.id,
            assessmentId: assessmentQuestions.assessmentId,
            sectionId: assessmentQuestions.sectionId,
            order: assessmentQuestions.order,
            overridePoints: assessmentQuestions.overridePoints,
            questionBankItemId: assessmentQuestions.questionBankItemId,
            questionText: questionBankItems.questionText,
            questionHtml: questionBankItems.questionHtml,
            imageUrl: questionBankItems.imageUrl,
            options: questionBankItems.options,
            type: questionBankItems.type,
            answerFormat: questionBankItems.answerFormat,
            rubricCriteria: questionBankItems.rubricCriteria,
            practicalConfig: questionBankItems.practicalConfig,
            modelAnswer: questionBankItems.modelAnswer,
            memo: questionBankItems.memo,
            points: questionBankItems.points,
            difficulty: questionBankItems.difficulty,
          })
          .from(assessmentQuestions)
          .innerJoin(questionBankItems, eq(assessmentQuestions.questionBankItemId, questionBankItems.id))
          .where(inArray(assessmentQuestions.sectionId, sectionIds))
          .orderBy(assessmentQuestions.order)
      : [];

  const sectionsWithQuestions = sections.map((s) => ({
    ...s,
    questions: questions.filter((q) => q.sectionId === s.id),
  }));

  return { ...paper, sections: sectionsWithQuestions };
}

export async function updatePaper(id: number, input: UpdatePaperInput) {
  const paper = await getPaperOrThrow(id);
  if (paper.status !== "draft") {
    throw new HttpError("Only draft papers can be edited", 400);
  }

  const [updated] = await db
    .update(assessments)
    .set({ ...input, updatedAt: new Date() })
    .where(eq(assessments.id, id))
    .returning();
  return updated;
}

export async function deletePaper(id: number) {
  const paper = await getPaperOrThrow(id);
  if (paper.status !== "draft") {
    throw new HttpError("Only draft papers can be deleted", 400);
  }
  await db.delete(assessments).where(eq(assessments.id, id));
}

// ── State transitions ─────────────────────────────────────────────────────────

export async function publishPaper(id: number) {
  const paper = await getPaperOrThrow(id);
  if (paper.status !== "draft") {
    throw new HttpError(`Cannot publish: paper is '${paper.status}', expected 'draft'`, 400);
  }

  // Guard: must have at least one section with one question
  const [{ value: sectionCount }] = await db
    .select({ value: count() })
    .from(assessmentSections)
    .where(eq(assessmentSections.assessmentId, id));
  if (Number(sectionCount) === 0) {
    throw new HttpError("Paper must have at least one section before publishing", 400);
  }
  const [{ value: qCount }] = await db
    .select({ value: count() })
    .from(assessmentQuestions)
    .where(eq(assessmentQuestions.assessmentId, id));
  if (Number(qCount) === 0) {
    throw new HttpError("Paper must have at least one question before publishing", 400);
  }
  const [{ value: assignmentCount }] = await db
    .select({ value: count() })
    .from(paperAssignments)
    .where(eq(paperAssignments.assessmentId, id));
  if (Number(assignmentCount) === 0) {
    throw new HttpError("Paper must be assigned to at least one student before publishing", 400);
  }

  const [updated] = await db
    .update(assessments)
    .set({ status: "published", updatedAt: new Date() })
    .where(eq(assessments.id, id))
    .returning();
  return updated;
}

export async function closePaper(id: number) {
  const paper = await getPaperOrThrow(id);
  if (paper.status !== "published") {
    throw new HttpError(`Cannot close: paper is '${paper.status}', expected 'published'`, 400);
  }
  const [updated] = await db
    .update(assessments)
    .set({ status: "closed", updatedAt: new Date() })
    .where(eq(assessments.id, id))
    .returning();
  return updated;
}

export async function startMarkingPaper(id: number) {
  const paper = await getPaperOrThrow(id);
  if (paper.status !== "closed") {
    throw new HttpError(`Cannot start marking: paper is '${paper.status}', expected 'closed'`, 400);
  }
  const [updated] = await db
    .update(assessments)
    .set({ status: "marking", updatedAt: new Date() })
    .where(eq(assessments.id, id))
    .returning();
  return updated;
}

export async function releasePaper(id: number) {
  const paper = await getPaperOrThrow(id);
  if (paper.status !== "marking") {
    throw new HttpError(`Cannot release: paper is '${paper.status}', expected 'marking'`, 400);
  }

  // Guard: all submitted answers must be marked (score not null)
  const [{ value: unmarkedCount }] = await db
    .select({ value: count() })
    .from(attemptAnswers)
    .innerJoin(assessmentAttempts, eq(attemptAnswers.attemptId, assessmentAttempts.id))
    .where(
      and(
        eq(assessmentAttempts.assessmentId, id),
        isNull(attemptAnswers.score),
      ),
    );
  if (Number(unmarkedCount) > 0) {
    throw new HttpError(
      `Cannot release: ${unmarkedCount} answer(s) are still unmarked`,
      400,
    );
  }

  // Update all graded attempts to 'released'
  await db
    .update(assessmentAttempts)
    .set({ status: "released" })
    .where(
      and(
        eq(assessmentAttempts.assessmentId, id),
        eq(assessmentAttempts.status, "graded"),
      ),
    );

  const [updated] = await db
    .update(assessments)
    .set({ status: "released", updatedAt: new Date() })
    .where(eq(assessments.id, id))
    .returning();
  return updated;
}

// ── Sections ──────────────────────────────────────────────────────────────────

export async function addSection(paperId: number, input: CreateSectionInput) {
  await getPaperOrThrow(paperId);
  const [section] = await db
    .insert(assessmentSections)
    .values({
      assessmentId: paperId,
      label: input.label,
      title: input.title,
      instructions: input.instructions,
      totalMarks: input.totalMarks,
      order: input.order,
      strictMode: input.strictMode ?? false,
    })
    .returning();
  return section;
}

export async function updateSection(
  paperId: number,
  sectionId: number,
  input: Partial<CreateSectionInput>,
) {
  await getPaperOrThrow(paperId);
  const [updated] = await db
    .update(assessmentSections)
    .set(input)
    .where(
      and(
        eq(assessmentSections.id, sectionId),
        eq(assessmentSections.assessmentId, paperId),
      ),
    )
    .returning();
  if (!updated) throw new HttpError("Section not found", 404);
  return updated;
}

export async function deleteSection(paperId: number, sectionId: number) {
  await getPaperOrThrow(paperId);
  await db
    .delete(assessmentSections)
    .where(
      and(
        eq(assessmentSections.id, sectionId),
        eq(assessmentSections.assessmentId, paperId),
      ),
    );
}

// ── Questions ─────────────────────────────────────────────────────────────────

export async function addQuestionToSection(
  paperId: number,
  sectionId: number,
  input: AddQuestionInput,
) {
  await getPaperOrThrow(paperId);
  const [pq] = await db
    .insert(assessmentQuestions)
    .values({
      assessmentId: paperId,
      sectionId,
      questionBankItemId: input.questionBankItemId,
      overridePoints: input.overridePoints,
      order: input.order,
    })
    .returning();
  return pq;
}

export async function updatePaperQuestion(
  paperId: number,
  sectionId: number,
  pqId: number,
  input: { overridePoints?: number; order?: number },
) {
  await getPaperOrThrow(paperId);
  const [updated] = await db
    .update(assessmentQuestions)
    .set(input)
    .where(
      and(
        eq(assessmentQuestions.id, pqId),
        eq(assessmentQuestions.assessmentId, paperId),
        eq(assessmentQuestions.sectionId, sectionId),
      ),
    )
    .returning();
  if (!updated) throw new HttpError("Question not found", 404);
  return updated;
}

export async function removePaperQuestion(paperId: number, sectionId: number, pqId: number) {
  await getPaperOrThrow(paperId);
  await db
    .delete(assessmentQuestions)
    .where(
      and(
        eq(assessmentQuestions.id, pqId),
        eq(assessmentQuestions.assessmentId, paperId),
        eq(assessmentQuestions.sectionId, sectionId),
      ),
    );
}

// ── Assignments ───────────────────────────────────────────────────────────────

export async function assignPaper(
  paperId: number,
  input: AssignPaperInput,
  assignedBy: string,
) {
  const paper = await getPaperOrThrow(paperId);
  if (paper.status === "archived") {
    throw new HttpError("Cannot assign an archived paper", 400);
  }

  const tokens = Array.from(
    new Set(
      (input.studentIds ?? [])
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  );
  if (tokens.length === 0) {
    throw new HttpError("At least one student ID or email is required", 400);
  }

  const idTokens = tokens.filter((token) => !token.includes("@"));
  const emailTokens = tokens.filter((token) => token.includes("@"));
  const normalizedEmailTokens = Array.from(
    new Set(emailTokens.map((token) => token.toLowerCase())),
  );

  const lookupConditions = [];
  if (idTokens.length > 0) {
    lookupConditions.push(inArray(users.id, idTokens));
  }
  if (emailTokens.length > 0) {
    lookupConditions.push(inArray(users.email, emailTokens));
  }
  if (normalizedEmailTokens.length > 0) {
    lookupConditions.push(inArray(users.email, normalizedEmailTokens));
  }

  const matchedUsers =
    lookupConditions.length > 0
      ? await db
          .select({ id: users.id, email: users.email })
          .from(users)
          .where(or(...lookupConditions))
      : [];

  const userIdById = new Map(matchedUsers.map((u) => [u.id, u.id]));
  const userIdByEmail = new Map(
    matchedUsers.map((u) => [u.email.toLowerCase(), u.id]),
  );

  const unresolved: string[] = [];
  const resolvedStudentIds = Array.from(
    new Set(
      tokens
        .map((token) => {
          if (userIdById.has(token)) {
            return userIdById.get(token)!;
          }
          return userIdByEmail.get(token.toLowerCase()) ?? null;
        })
        .filter((value): value is string => {
          if (value) return true;
          return false;
        }),
    ),
  );

  for (const token of tokens) {
    if (userIdById.has(token) || userIdByEmail.has(token.toLowerCase())) {
      continue;
    }
    unresolved.push(token);
  }

  if (unresolved.length > 0) {
    throw new HttpError(
      `Could not resolve student ID/email: ${unresolved.join(", ")}`,
      400,
    );
  }

  const openAt = input.openAt ? new Date(input.openAt) : undefined;
  const closeAt = input.closeAt ? new Date(input.closeAt) : undefined;
  if (openAt && Number.isNaN(openAt.getTime())) {
    throw new HttpError("openAt must be a valid datetime", 400);
  }
  if (closeAt && Number.isNaN(closeAt.getTime())) {
    throw new HttpError("closeAt must be a valid datetime", 400);
  }
  if (openAt && closeAt && openAt > closeAt) {
    throw new HttpError("openAt must be before closeAt", 400);
  }

  const values = resolvedStudentIds.map((studentId) => ({
    assessmentId: paperId,
    studentId,
    assignedBy,
    openAt,
    closeAt,
    maxAttempts: Math.max(1, input.maxAttempts ?? 1),
  }));

  const inserted = await db
    .insert(paperAssignments)
    .values(values)
    .onConflictDoNothing()
    .returning();
  return inserted;
}

export async function listAssignments(paperId: number) {
  await getPaperOrThrow(paperId);
  return db
    .select({
      id: paperAssignments.id,
      studentId: paperAssignments.studentId,
      assignedBy: paperAssignments.assignedBy,
      openAt: paperAssignments.openAt,
      closeAt: paperAssignments.closeAt,
      maxAttempts: paperAssignments.maxAttempts,
      createdAt: paperAssignments.createdAt,
      studentName: users.name,
      studentEmail: users.email,
    })
    .from(paperAssignments)
    .innerJoin(users, eq(paperAssignments.studentId, users.id))
    .where(eq(paperAssignments.assessmentId, paperId))
    .orderBy(users.name);
}

export async function removeAssignment(paperId: number, assignmentId: number) {
  await getPaperOrThrow(paperId);
  await db
    .delete(paperAssignments)
    .where(
      and(
        eq(paperAssignments.id, assignmentId),
        eq(paperAssignments.assessmentId, paperId),
      ),
    );
}

// ── Submissions (marking) ─────────────────────────────────────────────────────

export async function listSubmissions(paperId: number) {
  await getPaperOrThrow(paperId);
  return db
    .select({
      id: assessmentAttempts.id,
      userId: assessmentAttempts.userId,
      status: assessmentAttempts.status,
      startedAt: assessmentAttempts.startedAt,
      submittedAt: assessmentAttempts.submittedAt,
      totalScore: assessmentAttempts.totalScore,
      maxScore: assessmentAttempts.maxScore,
      percentage: assessmentAttempts.percentage,
      gradedAt: assessmentAttempts.gradedAt,
      studentName: users.name,
    })
    .from(assessmentAttempts)
    .innerJoin(users, eq(assessmentAttempts.userId, users.id))
    .where(eq(assessmentAttempts.assessmentId, paperId))
    .orderBy(sql`${assessmentAttempts.submittedAt} desc`);
}

export async function getSubmission(paperId: number, attemptId: string) {
  await getPaperOrThrow(paperId);
  const [attempt] = await db
    .select()
    .from(assessmentAttempts)
    .where(
      and(
        eq(assessmentAttempts.id, attemptId),
        eq(assessmentAttempts.assessmentId, paperId),
      ),
    );
  if (!attempt) throw new HttpError("Submission not found", 404);

  const answers = await db
    .select({
      id: attemptAnswers.id,
      assessmentQuestionId: attemptAnswers.assessmentQuestionId,
      questionBankItemId: attemptAnswers.questionBankItemId,
      answer: attemptAnswers.answer,
      isCorrect: attemptAnswers.isCorrect,
      score: attemptAnswers.score,
      maxScore: attemptAnswers.maxScore,
      markerComment: attemptAnswers.markerComment,
      markedBy: attemptAnswers.markedBy,
      markedAt: attemptAnswers.markedAt,
      answeredAt: attemptAnswers.answeredAt,
      questionText: questionBankItems.questionText,
      type: questionBankItems.type,
      options: questionBankItems.options,
      answerFormat: questionBankItems.answerFormat,
      rubricCriteria: questionBankItems.rubricCriteria,
      practicalConfig: questionBankItems.practicalConfig,
      modelAnswer: questionBankItems.modelAnswer,
      memo: questionBankItems.memo,
      correctAnswer: questionBankItems.correctAnswer,
      explanation: questionBankItems.explanation,
      points: questionBankItems.points,
      sectionId: assessmentQuestions.sectionId,
      questionOrder: assessmentQuestions.order,
      overridePoints: assessmentQuestions.overridePoints,
    })
    .from(attemptAnswers)
    .innerJoin(questionBankItems, eq(attemptAnswers.questionBankItemId, questionBankItems.id))
    .innerJoin(assessmentQuestions, eq(attemptAnswers.assessmentQuestionId, assessmentQuestions.id))
    .where(eq(attemptAnswers.attemptId, attemptId))
    .orderBy(assessmentQuestions.order);

  return { ...attempt, answers };
}

export async function markAnswer(
  paperId: number,
  attemptId: string,
  answerId: number,
  input: MarkAnswerInput,
  markerId: string,
) {
  await getPaperOrThrow(paperId);
  const [updated] = await db
    .update(attemptAnswers)
    .set({
      score: input.score,
      markerComment: input.markerComment,
      markedBy: markerId,
      markedAt: new Date(),
    })
    .where(
      and(
        eq(attemptAnswers.id, answerId),
        eq(attemptAnswers.attemptId, attemptId),
      ),
    )
    .returning();
  if (!updated) throw new HttpError("Answer not found", 404);
  return updated;
}

export async function finalizeMarking(paperId: number, attemptId: string, gradedBy: string) {
  await getPaperOrThrow(paperId);

  const [attempt] = await db
    .select()
    .from(assessmentAttempts)
    .where(
      and(
        eq(assessmentAttempts.id, attemptId),
        eq(assessmentAttempts.assessmentId, paperId),
      ),
    );
  if (!attempt) throw new HttpError("Submission not found", 404);

  const [{ value: unmarkedCount }] = await db
    .select({ value: count() })
    .from(attemptAnswers)
    .where(
      and(
        eq(attemptAnswers.attemptId, attemptId),
        isNull(attemptAnswers.score),
      ),
    );
  if (Number(unmarkedCount) > 0) {
    throw new HttpError(
      `Cannot finalize marking: ${unmarkedCount} answer(s) are still unmarked`,
      400,
    );
  }

  // Tally scores
  const answers = await db
    .select({ score: attemptAnswers.score, maxScore: attemptAnswers.maxScore })
    .from(attemptAnswers)
    .where(eq(attemptAnswers.attemptId, attemptId));

  const totalScore = answers.reduce((acc, a) => acc + (a.score ?? 0), 0);
  const maxScore = answers.reduce((acc, a) => acc + (a.maxScore ?? 0), 0);
  const percentage = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;

  const [updated] = await db
    .update(assessmentAttempts)
    .set({
      status: "graded",
      totalScore,
      maxScore,
      percentage,
      gradedBy,
      gradedAt: new Date(),
    })
    .where(
      and(
        eq(assessmentAttempts.id, attemptId),
        eq(assessmentAttempts.assessmentId, paperId),
      ),
    )
    .returning();
  if (!updated) throw new HttpError("Submission not found", 404);
  return updated;
}

// ── Student-facing ─────────────────────────────────────────────────────────────

export async function getMyPapers(studentId: string) {
  const now = new Date();
  const assignments = await db
    .select({
      assessmentId: paperAssignments.assessmentId,
      openAt: paperAssignments.openAt,
      closeAt: paperAssignments.closeAt,
      maxAttempts: paperAssignments.maxAttempts,
      title: assessments.title,
      grade: assessments.grade,
      totalMarks: assessments.totalMarks,
      timeLimitMinutes: assessments.timeLimitMinutes,
      status: assessments.status,
      instructions: assessments.instructions,
    })
    .from(paperAssignments)
    .innerJoin(assessments, eq(paperAssignments.assessmentId, assessments.id))
    .where(
      and(
        eq(paperAssignments.studentId, studentId),
        inArray(assessments.status, ["published", "closed", "marking", "released"]),
      ),
    )
    .orderBy(sql`${paperAssignments.createdAt} desc`);

  return assignments;
}

export async function startPaper(paperId: number, studentId: string) {
  const paper = await getPaperOrThrow(paperId);
  if (paper.status !== "published") {
    throw new HttpError("Paper is not available for taking", 400);
  }

  // Validate assignment
  const [assignment] = await db
    .select()
    .from(paperAssignments)
    .where(
      and(
        eq(paperAssignments.assessmentId, paperId),
        eq(paperAssignments.studentId, studentId),
      ),
    );
  if (!assignment) throw new HttpError("You are not assigned to this paper", 403);

  // Check open/close window
  const now = new Date();
  if (assignment.openAt && now < assignment.openAt) {
    throw new HttpError("This paper is not open yet", 400);
  }
  if (assignment.closeAt && now > assignment.closeAt) {
    throw new HttpError("This paper is closed", 400);
  }

  const [activeAttempt] = await db
    .select()
    .from(assessmentAttempts)
    .where(
      and(
        eq(assessmentAttempts.assessmentId, paperId),
        eq(assessmentAttempts.userId, studentId),
        eq(assessmentAttempts.status, "in_progress"),
      ),
    )
    .limit(1);
  if (activeAttempt) {
    return activeAttempt;
  }

  // Check attempt count
  const [{ value: attemptCount }] = await db
    .select({ value: count() })
    .from(assessmentAttempts)
    .where(
      and(
        eq(assessmentAttempts.assessmentId, paperId),
        eq(assessmentAttempts.userId, studentId),
      ),
    );
  if (Number(attemptCount) >= assignment.maxAttempts) {
    throw new HttpError("Maximum attempts reached", 400);
  }

  // Create attempt
  const attemptId = randomUUID();
  const [attempt] = await db
    .insert(assessmentAttempts)
    .values({
      id: attemptId,
      assessmentId: paperId,
      userId: studentId,
      status: "in_progress",
    })
    .returning();
  return attempt;
}

export async function getPaperResult(paperId: number, studentId: string) {
  const paper = await getPaperOrThrow(paperId);
  if (paper.status !== "released") {
    throw new HttpError("Results are not available yet", 403);
  }

  const [attempt] = await db
    .select()
    .from(assessmentAttempts)
    .where(
      and(
        eq(assessmentAttempts.assessmentId, paperId),
        eq(assessmentAttempts.userId, studentId),
        eq(assessmentAttempts.status, "released"),
      ),
    )
    .orderBy(sql`${assessmentAttempts.submittedAt} desc`)
    .limit(1);
  if (!attempt) throw new HttpError("Result not found", 404);

  return getSubmission(paperId, attempt.id);
}
