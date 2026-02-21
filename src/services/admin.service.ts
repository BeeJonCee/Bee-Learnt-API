import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { modules, quizAttempts, users } from "../core/database/schema/index.js";
import { syncAllUsersToNeonAuth, verifySchemaConsistency } from "../shared/utils/schema-sync.js";

export async function getAnalytics() {
  const [userCount] = await db.select({ count: sql<number>`count(*)` }).from(users);
  const [moduleCount] = await db.select({ count: sql<number>`count(*)` }).from(modules);

  // Active users in the last 7 days (based on progress_tracking or quiz_attempts)
  const activeResult = await db.execute<{ count: number }>(sql`
    SELECT COUNT(DISTINCT user_id)::int as count
    FROM (
      SELECT user_id FROM progress_tracking WHERE updated_at >= CURRENT_DATE - INTERVAL '7 days'
      UNION
      SELECT user_id FROM quiz_attempts WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
    ) active
  `);
  const activeThisWeek = activeResult.rows[0]?.count ?? 0;

  // Average quiz score
  const avgResult = await db.execute<{ avg: number }>(sql`
    SELECT COALESCE(
      ROUND(AVG(CASE WHEN max_score > 0 THEN (score::decimal / max_score) * 100 ELSE NULL END)),
      0
    )::int as avg
    FROM quiz_attempts
  `);
  const avgQuizScore = avgResult.rows[0]?.avg ?? 0;

  // Students by grade
  const gradeResult = await db.execute<{ grade: number; count: number }>(sql`
    SELECT sp.grade::int as grade, COUNT(*)::int as count
    FROM student_profiles sp
    WHERE sp.grade IS NOT NULL
    GROUP BY sp.grade
    ORDER BY sp.grade
  `);

  return {
    totalUsers: userCount?.count ?? 0,
    activeThisWeek,
    totalModules: moduleCount?.count ?? 0,
    avgQuizScore,
    studentsByGrade: gradeResult.rows.map((r) => ({
      grade: r.grade,
      count: r.count,
    })),
  };
}

/**
 * Sync all users from public schema to neon_auth schema
 * Call this after enabling Neon Auth integration
 */
export async function syncUsersToNeonAuth() {
  return syncAllUsersToNeonAuth();
}

/**
 * Verify schema consistency between neon_auth and public schemas
 */
export async function checkSchemaConsistency() {
  return verifySchemaConsistency();
}
