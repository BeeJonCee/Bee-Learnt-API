import { db } from "../core/database/index.js";
import { lessons, subjects, modules, quizzes, quizAttempts, progressTracking as progress } from "../core/database/schema/index.js";
import { eq, and } from "drizzle-orm";
import { sql } from "drizzle-orm";

export type SubjectPerformance = {
  subjectId: number;
  subjectName: string;
  lessonsCompleted: number;
  lessonsTotal: number;
  quizzesAttempted: number;
  averageScore: number;
  bestScore: number;
  lastActivityDate: string | null;
  strength: "excellent" | "good" | "satisfactory" | "needs_improvement";
  engagement: "high" | "medium" | "low";
  topicPerformance: {
    topic: string;
    averageScore: number;
    attempts: number;
  }[];
};

export type StudentPerformance = {
  userId: string;
  overallAverage: number;
  bestSubject: string;
  consistencyScore: number; // 0-100
  subjectCount: number;
  subjects: SubjectPerformance[];
  improvementAreas: {
    subject: string;
    topic: string;
    averageScore: number;
    recommendation: string;
  }[];
  learningVelocity: number; // points per week
  totalQuizzesAttempted: number;
  totalLessonsCompleted: number;
};

export async function getStudentPerformance(userId: string): Promise<StudentPerformance> {
  try {
    // Get all subjects with lessons data (join through modules)
    const subjectData = await db
      .select({
        subjectId: subjects.id,
        subjectName: subjects.name,
        lessonsCompleted: sql<number>`COUNT(DISTINCT CASE WHEN ${progress.completed} = true THEN ${progress.lessonId} END)`.mapWith(Number),
        lessonsTotal: sql<number>`COUNT(DISTINCT ${lessons.id})`.mapWith(Number),
        quizzesAttempted: sql<number>`COUNT(DISTINCT ${quizAttempts.id})`.mapWith(Number),
        averageScore: sql<number>`ROUND(AVG(CASE WHEN ${quizAttempts.score} IS NOT NULL THEN ${quizAttempts.score} ELSE 0 END), 2)`.mapWith(Number),
        bestScore: sql<number>`MAX(CASE WHEN ${quizAttempts.score} IS NOT NULL THEN ${quizAttempts.score} ELSE 0 END)`.mapWith(Number),
        lastActivityDate: sql<string>`MAX(${progress.updatedAt})`,
      })
      .from(subjects)
      .leftJoin(modules, eq(modules.subjectId, subjects.id))
      .leftJoin(lessons, eq(lessons.moduleId, modules.id))
      .leftJoin(progress, and(eq(progress.userId, userId), eq(progress.lessonId, lessons.id)))
      .leftJoin(quizzes, eq(quizzes.moduleId, modules.id))
      .leftJoin(
        quizAttempts,
        and(eq(quizAttempts.userId, userId), eq(quizAttempts.quizId, quizzes.id))
      )
      .groupBy(subjects.id, subjects.name);

    // Calculate subject performance details
    const subjects_performance: SubjectPerformance[] = subjectData.map((sub) => {
      const averageScore = sub.averageScore || 0;
      let strength: SubjectPerformance["strength"] = "needs_improvement";
      if (averageScore >= 85) strength = "excellent";
      else if (averageScore >= 75) strength = "good";
      else if (averageScore >= 60) strength = "satisfactory";

      let engagement: SubjectPerformance["engagement"] = "low";
      if (sub.lessonsCompleted > 10) engagement = "high";
      else if (sub.lessonsCompleted > 5) engagement = "medium";

      return {
        subjectId: sub.subjectId,
        subjectName: sub.subjectName,
        lessonsCompleted: sub.lessonsCompleted || 0,
        lessonsTotal: sub.lessonsTotal || 0,
        quizzesAttempted: sub.quizzesAttempted || 0,
        averageScore: averageScore,
        bestScore: sub.bestScore || 0,
        lastActivityDate: sub.lastActivityDate,
        strength,
        engagement,
        topicPerformance: [], // Populated separately if needed
      };
    });

    // Calculate overall metrics
    const totalQuizzesAttempted = subjects_performance.reduce(
      (sum, s) => sum + (s.quizzesAttempted || 0),
      0
    );
    const totalLessonsCompleted = subjects_performance.reduce(
      (sum, s) => sum + (s.lessonsCompleted || 0),
      0
    );
    const overallAverage =
      subjects_performance.length > 0
        ? subjects_performance.reduce((sum, s) => sum + s.averageScore, 0) /
          subjects_performance.length
        : 0;

    const bestSubject =
      subjects_performance.length > 0
        ? subjects_performance.reduce((best, curr) =>
            curr.averageScore > best.averageScore ? curr : best
          ).subjectName
        : "N/A";

    // Calculate consistency (standard deviation of scores)
    const consistencyScore = calculateConsistency(
      subjects_performance.map((s) => s.averageScore)
    );

    // Identify improvement areas
    const improvementAreas = subjects_performance
      .filter((s) => s.strength === "needs_improvement" || s.strength === "satisfactory")
      .map((s) => ({
        subject: s.subjectName,
        topic: "General topics",
        averageScore: s.averageScore,
        recommendation: `Focus on ${s.subjectName}. Try reviewing core concepts and attempting more practice quizzes.`,
      }));

    // Calculate learning velocity (points gained per week)
    const learningVelocity = await calculateLearningVelocity(userId);

    return {
      userId,
      overallAverage: Math.round(overallAverage * 100) / 100,
      bestSubject,
      consistencyScore,
      subjectCount: subjects_performance.length,
      subjects: subjects_performance,
      improvementAreas,
      learningVelocity,
      totalQuizzesAttempted,
      totalLessonsCompleted,
    };
  } catch (error) {
    console.error("Error fetching student performance:", error);
    throw error;
  }
}

function calculateConsistency(scores: number[]): number {
  if (scores.length === 0) return 100;
  if (scores.length === 1) return 100;

  const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
  const squaredDiffs = scores.map((score) => Math.pow(score - mean, 2));
  const avgSquaredDiff = squaredDiffs.reduce((a, b) => a + b, 0) / scores.length;
  const stdDev = Math.sqrt(avgSquaredDiff);

  // Convert stdDev to consistency score (lower stdDev = higher consistency)
  // Max stdDev of 50 = 0% consistency, 0 stdDev = 100% consistency
  const consistency = Math.max(0, 100 - (stdDev / 50) * 100);
  return Math.round(consistency);
}

async function calculateLearningVelocity(userId: string): Promise<number> {
  try {
    // Get quiz attempts from the last 7 days
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const weeklyAttempts = await db
      .select({
        totalScore: sql<number>`SUM(${quizAttempts.score})`.mapWith(Number),
      })
      .from(quizAttempts)
      .where(
        and(
          eq(quizAttempts.userId, userId),
          sql`${quizAttempts.createdAt} >= ${sevenDaysAgo.toISOString()}`
        )
      )
      .then((rows) => rows[0]?.totalScore || 0);

    return Math.round(weeklyAttempts / 7);
  } catch (error) {
    console.error("Error calculating learning velocity:", error);
    return 0;
  }
}

export async function getSubjectAnalytics(userId: string, subjectId: number) {
  try {
    // Group analytics by module (modules represent topic areas within a subject)
    const analytics = await db
      .select({
        topicName: modules.title,
        lessonsCompleted: sql<number>`COUNT(DISTINCT CASE WHEN ${progress.completed} = true THEN ${progress.lessonId} END)`.mapWith(Number),
        lessonsTotal: sql<number>`COUNT(DISTINCT ${lessons.id})`.mapWith(Number),
        averageScore: sql<number>`ROUND(AVG(${quizAttempts.score}), 2)`.mapWith(Number),
        bestScore: sql<number>`MAX(${quizAttempts.score})`.mapWith(Number),
        quizAttempts: sql<number>`COUNT(${quizAttempts.id})`.mapWith(Number),
      })
      .from(modules)
      .where(eq(modules.subjectId, subjectId))
      .leftJoin(lessons, eq(lessons.moduleId, modules.id))
      .leftJoin(progress, and(eq(progress.userId, userId), eq(progress.lessonId, lessons.id)))
      .leftJoin(quizzes, eq(quizzes.moduleId, modules.id))
      .leftJoin(
        quizAttempts,
        and(eq(quizAttempts.userId, userId), eq(quizAttempts.quizId, quizzes.id))
      )
      .groupBy(modules.id, modules.title)
      .orderBy(modules.title);

    return analytics;
  } catch (error) {
    console.error("Error fetching subject analytics:", error);
    throw error;
  }
}
