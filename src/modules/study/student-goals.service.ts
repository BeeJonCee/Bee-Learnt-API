import { db } from "../../core/database/index.js";
import { studyGoals } from "../../core/database/schema/index.js";
import { eq, and, desc } from "drizzle-orm";
import { isMissingRelationError } from "../../shared/utils/db-errors.js";
import { HttpError } from "../../shared/utils/http-error.js";
import { logWarn } from "../../shared/utils/logger.js";

export type StudyGoal = {
  id: string;
  userId: string;
  title: string;
  description: string | null;
  targetHours: number;
  currentHours: number;
  deadline: Date;
  status: "active" | "completed" | "overdue" | "abandoned";
  priority: "low" | "medium" | "high";
  createdAt: Date;
  updatedAt: Date;
};

let hasLoggedMissingStudyGoalsTable = false;

function logMissingStudyGoalsTableOnce(error: unknown) {
  if (hasLoggedMissingStudyGoalsTable) return;
  hasLoggedMissingStudyGoalsTable = true;
  logWarn("Study goals table is missing; returning safe fallback response.", {
    code: (error as { code?: string } | undefined)?.code,
    message: (error as { message?: string } | undefined)?.message,
  });
}

function throwStudyGoalsUnavailable(error: unknown): never {
  if (isMissingRelationError(error)) {
    logMissingStudyGoalsTableOnce(error);
    throw new HttpError(
      "Study goals feature is not ready yet. Please run database migrations.",
      503
    );
  }
  throw error;
}

export async function getStudentGoals(userId: string): Promise<StudyGoal[]> {
  try {
    const goals = await db
      .select()
      .from(studyGoals)
      .where(eq(studyGoals.userId, userId))
      .orderBy(desc(studyGoals.createdAt));

    return goals as StudyGoal[];
  } catch (error) {
    if (isMissingRelationError(error)) {
      logMissingStudyGoalsTableOnce(error);
      return [];
    }
    throw error;
  }
}

export async function createStudyGoal(
  userId: string,
  data: Omit<StudyGoal, "id" | "userId" | "createdAt" | "updatedAt" | "currentHours">
): Promise<StudyGoal> {
  try {
    const now = new Date();
    const newGoal: StudyGoal = {
      id: `goal_${Date.now()}`,
      userId,
      title: data.title,
      description: data.description,
      targetHours: data.targetHours,
      currentHours: 0,
      deadline: data.deadline instanceof Date ? data.deadline : new Date(data.deadline),
      status: "active",
      priority: data.priority,
      createdAt: now,
      updatedAt: now,
    };

    await db.insert(studyGoals).values(newGoal);
    return newGoal;
  } catch (error) {
    throwStudyGoalsUnavailable(error);
  }
}

export async function updateStudyGoal(
  goalId: string,
  userId: string,
  data: Partial<Omit<StudyGoal, "id" | "userId" | "createdAt">>
): Promise<StudyGoal> {
  try {
    const now = new Date();
    const { deadline, ...rest } = data;
    const updates: Record<string, unknown> = {
      ...rest,
      updatedAt: now,
    };
    if (deadline !== undefined) {
      updates.deadline = deadline instanceof Date ? deadline : new Date(deadline);
    }

    await db
      .update(studyGoals)
      .set(updates as any)
      .where(and(eq(studyGoals.id, goalId), eq(studyGoals.userId, userId)));

    const updatedGoal = await db
      .select()
      .from(studyGoals)
      .where(and(eq(studyGoals.id, goalId), eq(studyGoals.userId, userId)))
      .then((rows) => rows[0]);

    return updatedGoal as StudyGoal;
  } catch (error) {
    throwStudyGoalsUnavailable(error);
  }
}

export async function completeStudyGoal(
  goalId: string,
  userId: string
): Promise<StudyGoal> {
  try {
    const now = new Date();

    await db
      .update(studyGoals)
      .set({
        status: "completed",
        updatedAt: now,
      })
      .where(and(eq(studyGoals.id, goalId), eq(studyGoals.userId, userId)));

    const completedGoal = await db
      .select()
      .from(studyGoals)
      .where(and(eq(studyGoals.id, goalId), eq(studyGoals.userId, userId)))
      .then((rows) => rows[0]);

    return completedGoal as StudyGoal;
  } catch (error) {
    throwStudyGoalsUnavailable(error);
  }
}

export async function deleteStudyGoal(
  goalId: string,
  userId: string
): Promise<void> {
  try {
    await db
      .delete(studyGoals)
      .where(and(eq(studyGoals.id, goalId), eq(studyGoals.userId, userId)));
  } catch (error) {
    throwStudyGoalsUnavailable(error);
  }
}

export async function updateGoalProgress(
  goalId: string,
  userId: string,
  hoursSpent: number
): Promise<StudyGoal> {
  try {
    // Get current goal
    const goal = await db
      .select()
      .from(studyGoals)
      .where(and(eq(studyGoals.id, goalId), eq(studyGoals.userId, userId)))
      .then((rows) => rows[0]);

    if (!goal) {
      throw new Error("Goal not found");
    }

    // Update goal with accumulated hours
    const newCurrentHours = (goal.currentHours || 0) + hoursSpent;
    const now = new Date();

    // Determine status based on completion
    let status = "active";
    if (newCurrentHours >= goal.targetHours) {
      status = "completed";
    } else if (goal.deadline < now) {
      status = "overdue";
    }

    await db
      .update(studyGoals)
      .set({
        currentHours: newCurrentHours,
        status: status as any,
        updatedAt: now,
      })
      .where(and(eq(studyGoals.id, goalId), eq(studyGoals.userId, userId)));

    const updatedGoal = await db
      .select()
      .from(studyGoals)
      .where(and(eq(studyGoals.id, goalId), eq(studyGoals.userId, userId)))
      .then((rows) => rows[0]);

    return updatedGoal as StudyGoal;
  } catch (error) {
    throwStudyGoalsUnavailable(error);
  }
}
