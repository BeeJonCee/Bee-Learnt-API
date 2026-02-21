import { and, desc, eq, gte, sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import {
  users,
  roles,
  assessmentAttempts,
  attemptAnswers,
  subjects,
  topicMastery,
  topics,
  questionBankItems,
  studySessions,
  streaks,
  userPoints,
} from "../core/database/schema/index.js";

// ============ PLATFORM ANALYTICS (Admin) ============

export async function getPlatformStats() {
  // User counts by role
  const userStats = await db
    .select({
      role: roles.name,
      count: sql<number>`count(*)::int`,
    })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id))
    .groupBy(roles.name);

  // Active users (logged in last 7 days)
  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

  const [activeUsers] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(users)
    .where(gte(users.lastLoginAt, sevenDaysAgo));

  // Assessment stats
  const [assessmentStats] = await db
    .select({
      totalAttempts: sql<number>`count(*)::int`,
      completedAttempts: sql<number>`count(*) filter (where status = 'graded' or status = 'submitted')::int`,
      averageScore: sql<number>`avg(percentage)::int`,
    })
    .from(assessmentAttempts);

  // Question bank stats
  const [questionStats] = await db
    .select({
      total: sql<number>`count(*)::int`,
      active: sql<number>`count(*) filter (where is_active = true)::int`,
    })
    .from(questionBankItems);

  // Study session stats (last 30 days)
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  const [studyStats] = await db
    .select({
      totalSessions: sql<number>`count(*)::int`,
      totalMinutes: sql<number>`coalesce(sum(duration_minutes), 0)::int`,
    })
    .from(studySessions)
    .where(gte(studySessions.startedAt, thirtyDaysAgo));

  return {
    users: {
      byRole: userStats.reduce(
        (acc, { role, count }) => ({ ...acc, [role]: count }),
        {} as Record<string, number>
      ),
      activeLastWeek: activeUsers.count,
    },
    assessments: {
      totalAttempts: assessmentStats.totalAttempts ?? 0,
      completedAttempts: assessmentStats.completedAttempts ?? 0,
      averageScore: assessmentStats.averageScore ?? 0,
    },
    questions: {
      total: questionStats.total ?? 0,
      active: questionStats.active ?? 0,
    },
    study: {
      sessionsLast30Days: studyStats.totalSessions ?? 0,
      minutesLast30Days: studyStats.totalMinutes ?? 0,
    },
  };
}

// ============ SUBJECT ANALYTICS ============

export async function getSubjectAnalytics(subjectId: number) {
  // Get subject info
  const [subject] = await db
    .select()
    .from(subjects)
    .where(eq(subjects.id, subjectId));

  if (!subject) return null;

  // Question stats by difficulty
  const questionStats = await db
    .select({
      difficulty: questionBankItems.difficulty,
      count: sql<number>`count(*)::int`,
    })
    .from(questionBankItems)
    .where(
      and(
        eq(questionBankItems.subjectId, subjectId),
        eq(questionBankItems.isActive, true)
      )
    )
    .groupBy(questionBankItems.difficulty);

  // Average score for assessments in this subject
  const scoreStats = await db.execute(sql`
    SELECT
      COALESCE(AVG(aa.percentage), 0)::int as avg_score,
      COUNT(*)::int as attempt_count
    FROM assessment_attempts aa
    JOIN assessments a ON aa.assessment_id = a.id
    WHERE a.subject_id = ${subjectId}
      AND aa.status IN ('graded', 'submitted')
  `);

  // Topic mastery distribution
  const masteryDistribution = await db.execute(sql`
    SELECT
      CASE
        WHEN mastery_percent < 25 THEN 'Needs Work (0-24%)'
        WHEN mastery_percent < 50 THEN 'Developing (25-49%)'
        WHEN mastery_percent < 75 THEN 'Proficient (50-74%)'
        ELSE 'Mastered (75-100%)'
      END as mastery_range,
      COUNT(DISTINCT user_id)::int as student_count
    FROM topic_mastery tm
    JOIN topics t ON tm.topic_id = t.id
    WHERE t.subject_id = ${subjectId}
    GROUP BY mastery_range
    ORDER BY mastery_range
  `);

  return {
    subject,
    questions: {
      byDifficulty: questionStats.reduce(
        (acc, { difficulty, count }) => ({ ...acc, [difficulty]: count }),
        {} as Record<string, number>
      ),
      total: questionStats.reduce((sum, { count }) => sum + count, 0),
    },
    performance: {
      averageScore: (scoreStats.rows[0] as any)?.avg_score ?? 0,
      attemptCount: (scoreStats.rows[0] as any)?.attempt_count ?? 0,
    },
    masteryDistribution: masteryDistribution.rows,
  };
}

// ============ TOPIC MASTERY HEATMAP ============

export async function getTopicMasteryHeatmap(filters: {
  subjectId?: number;
  gradeId?: number;
}) {
  const conditions: any[] = [];

  if (filters.subjectId) {
    conditions.push(eq(topics.subjectId, filters.subjectId));
  }
  if (filters.gradeId) {
    conditions.push(eq(topics.gradeId, filters.gradeId));
  }

  const masteryData = await db
    .select({
      topicId: topics.id,
      topicTitle: topics.title,
      subjectId: topics.subjectId,
      subjectName: subjects.name,
      avgMastery: sql<number>`coalesce(avg(${topicMastery.masteryPercent}), 0)::int`,
      studentCount: sql<number>`count(distinct ${topicMastery.userId})::int`,
    })
    .from(topics)
    .innerJoin(subjects, eq(topics.subjectId, subjects.id))
    .leftJoin(topicMastery, eq(topics.id, topicMastery.topicId))
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .groupBy(topics.id, topics.title, topics.subjectId, subjects.name)
    .orderBy(subjects.name, topics.order);

  return masteryData;
}

// ============ STUDENT ANALYTICS ============

export async function getStudentAnalytics(userId: string) {
  // Overall attempt stats
  const [attemptStats] = await db
    .select({
      totalAttempts: sql<number>`count(*)::int`,
      completedAttempts: sql<number>`count(*) filter (where status = 'graded' or status = 'submitted')::int`,
      averageScore: sql<number>`coalesce(avg(percentage), 0)::int`,
      bestScore: sql<number>`coalesce(max(percentage), 0)::int`,
    })
    .from(assessmentAttempts)
    .where(eq(assessmentAttempts.userId, userId));

  // Subject breakdown
  const subjectPerformance = await db.execute(sql`
    SELECT
      s.id as subject_id,
      s.name as subject_name,
      COUNT(*)::int as attempt_count,
      COALESCE(AVG(aa.percentage), 0)::int as avg_score
    FROM assessment_attempts aa
    JOIN assessments a ON aa.assessment_id = a.id
    JOIN subjects s ON a.subject_id = s.id
    WHERE aa.user_id = ${userId}::uuid
      AND aa.status IN ('graded', 'submitted')
    GROUP BY s.id, s.name
    ORDER BY s.name
  `);

  // Topic mastery
  const masteryStats = await db
    .select({
      topicId: topicMastery.topicId,
      topicTitle: topics.title,
      subjectName: subjects.name,
      masteryPercent: topicMastery.masteryPercent,
      totalQuestions: topicMastery.totalQuestions,
      correctAnswers: topicMastery.correctAnswers,
    })
    .from(topicMastery)
    .innerJoin(topics, eq(topicMastery.topicId, topics.id))
    .innerJoin(subjects, eq(topics.subjectId, subjects.id))
    .where(eq(topicMastery.userId, userId))
    .orderBy(desc(topicMastery.masteryPercent));

  // Streak and points
  const [streakData] = await db
    .select()
    .from(streaks)
    .where(eq(streaks.userId, userId));

  const [pointsData] = await db
    .select()
    .from(userPoints)
    .where(eq(userPoints.userId, userId));

  // Recent activity (last 10 attempts)
  const recentAttempts = await db
    .select({
      attemptId: assessmentAttempts.id,
      assessmentId: assessmentAttempts.assessmentId,
      status: assessmentAttempts.status,
      percentage: assessmentAttempts.percentage,
      submittedAt: assessmentAttempts.submittedAt,
    })
    .from(assessmentAttempts)
    .where(eq(assessmentAttempts.userId, userId))
    .orderBy(desc(assessmentAttempts.startedAt))
    .limit(10);

  return {
    overall: {
      totalAttempts: attemptStats.totalAttempts ?? 0,
      completedAttempts: attemptStats.completedAttempts ?? 0,
      averageScore: attemptStats.averageScore ?? 0,
      bestScore: attemptStats.bestScore ?? 0,
    },
    bySubject: subjectPerformance.rows,
    topicMastery: masteryStats,
    streak: streakData ?? { currentStreak: 0, longestStreak: 0, weeklyMinutes: 0 },
    points: pointsData ?? { totalXp: 0, level: 1, weeklyXp: 0 },
    recentAttempts,
  };
}

// ============ WEAK TOPICS ============

export async function getWeakTopics(userId: string, limit = 5) {
  const weakTopics = await db
    .select({
      topicId: topicMastery.topicId,
      topicTitle: topics.title,
      subjectId: topics.subjectId,
      subjectName: subjects.name,
      masteryPercent: topicMastery.masteryPercent,
      totalQuestions: topicMastery.totalQuestions,
      correctAnswers: topicMastery.correctAnswers,
      lastAttemptAt: topicMastery.lastAttemptAt,
    })
    .from(topicMastery)
    .innerJoin(topics, eq(topicMastery.topicId, topics.id))
    .innerJoin(subjects, eq(topics.subjectId, subjects.id))
    .where(eq(topicMastery.userId, userId))
    .orderBy(topicMastery.masteryPercent)
    .limit(limit);

  return weakTopics;
}

// ============ ASSESSMENT ANALYTICS ============

export async function getAssessmentAnalytics(assessmentId: number) {
  // Score distribution
  const scoreDistribution = await db.execute(sql`
    SELECT
      CASE
        WHEN percentage < 30 THEN '0-29%'
        WHEN percentage < 50 THEN '30-49%'
        WHEN percentage < 70 THEN '50-69%'
        WHEN percentage < 80 THEN '70-79%'
        WHEN percentage < 90 THEN '80-89%'
        ELSE '90-100%'
      END as score_range,
      COUNT(*)::int as count
    FROM assessment_attempts
    WHERE assessment_id = ${assessmentId}
      AND status IN ('graded', 'submitted')
      AND percentage IS NOT NULL
    GROUP BY score_range
    ORDER BY score_range
  `);

  // Overall stats
  const overallStats = await db.execute(sql`
    SELECT
      COUNT(*)::int as attempt_count,
      COALESCE(AVG(percentage), 0)::int as avg_score,
      COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY percentage), 0)::int as median_score,
      COALESCE(
        (COUNT(*) FILTER (WHERE percentage >= 50) * 100.0 / NULLIF(COUNT(*), 0)),
        0
      )::int as pass_rate
    FROM assessment_attempts
    WHERE assessment_id = ${assessmentId}
      AND status IN ('graded', 'submitted')
  `);

  // Question performance (which questions are hardest)
  const questionPerformance = await db.execute(sql`
    SELECT
      qb.id as question_id,
      LEFT(qb.question_text, 100) as question_text,
      COALESCE(
        (COUNT(*) FILTER (WHERE aa.is_correct = true) * 100.0 / NULLIF(COUNT(*), 0)),
        0
      )::int as correct_rate,
      COUNT(*)::int as attempt_count
    FROM attempt_answers aa
    JOIN question_bank_items qb ON aa.question_bank_item_id = qb.id
    JOIN assessment_attempts att ON aa.attempt_id = att.id
    WHERE att.assessment_id = ${assessmentId}
    GROUP BY qb.id, qb.question_text
    ORDER BY correct_rate ASC
    LIMIT 10
  `);

  return {
    scoreDistribution: scoreDistribution.rows,
    overall: (overallStats.rows[0] as any) ?? {
      attempt_count: 0,
      avg_score: 0,
      median_score: 0,
      pass_rate: 0,
    },
    hardestQuestions: questionPerformance.rows,
  };
}
