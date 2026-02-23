import { and, eq } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import {
  assignmentSubmissions,
  assignments,
} from "../../core/database/schema/index.js";
import type { RubricScore } from "../../core/database/schema/index.js";

export async function getSubmission(assignmentId: number, userId: string) {
  const [row] = await db
    .select()
    .from(assignmentSubmissions)
    .where(
      and(
        eq(assignmentSubmissions.assignmentId, assignmentId),
        eq(assignmentSubmissions.userId, userId),
      ),
    );
  return row ?? null;
}

export async function getSubmissionsByAssignment(assignmentId: number) {
  return db
    .select()
    .from(assignmentSubmissions)
    .where(eq(assignmentSubmissions.assignmentId, assignmentId))
    .orderBy(assignmentSubmissions.submittedAt);
}

export async function submitAssignment(
  assignmentId: number,
  userId: string,
  submissionText?: string,
) {
  // Upsert: if already submitted, update the text and reset submitted_at
  const existing = await getSubmission(assignmentId, userId);

  if (existing) {
    const [updated] = await db
      .update(assignmentSubmissions)
      .set({
        submissionText: submissionText ?? null,
        submittedAt: new Date(),
      })
      .where(eq(assignmentSubmissions.id, existing.id))
      .returning();
    // Mark assignment status as submitted
    await db
      .update(assignments)
      .set({ status: "submitted" })
      .where(eq(assignments.id, assignmentId));
    return updated;
  }

  const [created] = await db
    .insert(assignmentSubmissions)
    .values({ assignmentId, userId, submissionText })
    .returning();

  await db
    .update(assignments)
    .set({ status: "submitted" })
    .where(eq(assignments.id, assignmentId));

  return created;
}

type GradeInput = {
  rubricId?: number;
  rubricScores?: RubricScore[];
  totalScore?: number;
  maxScore?: number;
  feedback?: string;
};

export async function gradeSubmission(
  assignmentId: number,
  gradedBy: string,
  input: GradeInput,
) {
  // Calculate totalScore/maxScore from rubric scores if not provided explicitly
  let totalScore = input.totalScore;
  let maxScore = input.maxScore;

  if (input.rubricScores && input.rubricScores.length > 0 && totalScore === undefined) {
    totalScore = input.rubricScores.reduce((sum, s) => sum + s.score, 0);
  }

  const [updated] = await db
    .update(assignmentSubmissions)
    .set({
      rubricId: input.rubricId ?? null,
      rubricScores: input.rubricScores ?? null,
      totalScore: totalScore ?? null,
      maxScore: maxScore ?? null,
      feedback: input.feedback ?? null,
      gradedAt: new Date(),
      gradedBy,
    })
    .where(eq(assignmentSubmissions.assignmentId, assignmentId))
    .returning();

  if (!updated) return null;

  // Mark assignment as graded
  await db
    .update(assignments)
    .set({
      status: "graded",
      grade: totalScore ?? 0,
    })
    .where(eq(assignments.id, assignmentId));

  return updated;
}
