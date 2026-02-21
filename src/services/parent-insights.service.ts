import { db } from "../core/database/index.js";
import { sql } from "drizzle-orm";

export async function getParentInsights(parentId: string) {
  // Get all children for this parent with their progress stats
  const children = await db.execute<{
    student_id: string;
    student_name: string;
    completed_lessons: number;
    quiz_average: number;
    total_assignments: number;
    assignments_submitted: number;
  }>(
    sql`
      SELECT
        u.id as student_id,
        u.name as student_name,
        COALESCE(
          (SELECT COUNT(*)::int FROM progress_tracking pt
           WHERE pt.user_id = u.id AND pt.completed = true AND pt.lesson_id IS NOT NULL),
          0
        ) as completed_lessons,
        COALESCE(
          (SELECT ROUND(AVG(
            CASE WHEN qa.max_score > 0 THEN (qa.score::decimal / qa.max_score) * 100 ELSE NULL END
          ))::int
           FROM quiz_attempts qa
           WHERE qa.user_id = u.id),
          0
        ) as quiz_average,
        COALESCE(
          (SELECT COUNT(*)::int FROM assignments a
           INNER JOIN user_module_selections ums ON ums.module_id = a.module_id
           WHERE ums.user_id = u.id AND ums.status = 'unlocked'),
          0
        ) as total_assignments,
        COALESCE(
          (SELECT COUNT(*)::int FROM assignments a
           INNER JOIN user_module_selections ums ON ums.module_id = a.module_id
           WHERE ums.user_id = u.id AND ums.status = 'unlocked'
             AND a.status IN ('submitted', 'graded')),
          0
        ) as assignments_submitted
      FROM users u
      INNER JOIN parent_student_links psl ON u.id = psl.student_id
      WHERE psl.parent_id = ${parentId}
      ORDER BY u.name
    `
  );

  // Calculate aggregates
  const totalLessonsCompleted = children.rows.reduce(
    (sum: number, child: any) => sum + Number(child.completed_lessons),
    0,
  );
  const averageQuizScore =
    children.rows.length > 0
      ? Math.round(
          children.rows.reduce(
            (sum: number, child: any) => sum + Number(child.quiz_average),
            0,
          ) / children.rows.length,
        )
      : 0;
  const totalAssignmentsSubmitted = children.rows.reduce(
    (sum: number, child: any) => sum + Number(child.assignments_submitted),
    0,
  );

  // Get student IDs for trend query
  const studentIds = children.rows.map((c: any) => c.student_id);

  // 7-day learning trend
  let learningTrend: { date: string; averageScore: number; lessonsCompleted: number }[] = [];

  if (studentIds.length > 0) {
    const trendResult = await db.execute<{
      date: string;
      average_score: number;
      lessons_completed: number;
    }>(
      sql`
        WITH RECURSIVE dates AS (
          SELECT CURRENT_DATE - INTERVAL '6 days' AS date
          UNION ALL
          SELECT date + INTERVAL '1 day' FROM dates
          WHERE date < CURRENT_DATE
        ),
        child_ids AS (
          SELECT student_id FROM parent_student_links WHERE parent_id = ${parentId}
        )
        SELECT
          TO_CHAR(d.date, 'MM-DD') as date,
          COALESCE(ROUND(AVG(
            CASE WHEN qa.max_score > 0 THEN (qa.score::decimal / qa.max_score) * 100 ELSE NULL END
          )::numeric, 1), 0) as average_score,
          COALESCE(COUNT(DISTINCT pt.lesson_id)::int, 0) as lessons_completed
        FROM dates d
        LEFT JOIN quiz_attempts qa
          ON qa.created_at::date = d.date::date
          AND qa.user_id IN (SELECT student_id FROM child_ids)
        LEFT JOIN progress_tracking pt
          ON pt.updated_at::date = d.date::date
          AND pt.completed = true
          AND pt.lesson_id IS NOT NULL
          AND pt.user_id IN (SELECT student_id FROM child_ids)
        GROUP BY d.date
        ORDER BY d.date
      `
    );

    learningTrend = trendResult.rows.map((trend: any) => ({
      date: trend.date,
      averageScore: Number(trend.average_score) || 0,
      lessonsCompleted: Number(trend.lessons_completed) || 0,
    }));
  }

  return {
    children: children.rows.map((child: any) => ({
      studentId: child.student_id,
      studentName: child.student_name,
      completedLessons: Number(child.completed_lessons),
      quizAverage: Number(child.quiz_average),
      totalAssignments: Number(child.total_assignments),
      assignmentsSubmitted: Number(child.assignments_submitted),
    })),
    averageQuizScore,
    totalLessonsCompleted,
    totalAssignmentsSubmitted,
    learningTrend,
  };
}
