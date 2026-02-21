import type { Request, Response } from "express";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { getParentInsights } from "../services/parent-insights.service.js";

export const getParentOverview = asyncHandler(async (req: Request, res: Response) => {
  const parentId = req.user?.id ?? null;
  if (!parentId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const result = await db.execute(sql`
    SELECT
      u.id as "studentId",
      u.name as "studentName",
      COALESCE(p.completed_lessons, 0)::int as "completedLessons",
      COALESCE(q.quiz_average, 0)::int as "quizAverage"
    FROM parent_student_links psl
    JOIN users u ON u.id = psl.student_id
    LEFT JOIN (
      SELECT
        user_id,
        count(*) FILTER (
          WHERE completed = true AND lesson_id IS NOT NULL
        ) as completed_lessons
      FROM progress_tracking
      GROUP BY user_id
    ) p ON p.user_id = u.id
    LEFT JOIN (
      SELECT
        user_id,
        round(avg(
          CASE
            WHEN max_score > 0 THEN (score::decimal / max_score) * 100
            ELSE NULL
          END
        )) as quiz_average
      FROM quiz_attempts
      GROUP BY user_id
    ) q ON q.user_id = u.id
    WHERE psl.parent_id = ${parentId}
    ORDER BY u.name;
  `);

  res.json(result.rows);
});

export const getParentInsightsHandler = asyncHandler(
  async (req: Request, res: Response) => {
    const parentId = req.user?.id ?? null;
    if (!parentId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const insights = await getParentInsights(parentId);
    res.json(insights);
  }
);
