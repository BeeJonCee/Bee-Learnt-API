import { db } from "../../core/database/index.js";
import { sql, eq, and } from "drizzle-orm";
import { topicMastery, attemptAnswers, assessmentQuestions, questionBankItems } from "../../core/database/schema/index.js";

/**
 * Mastery Calculation Service
 * Tracks and updates topic mastery based on student performance
 */
export class MasteryService {
  /**
   * Update topic mastery for a user after completing an assessment
   * @param userId - The user's ID
   * @param attemptId - The assessment attempt ID
   */
  async updateMasteryAfterAttempt(userId: string, attemptId: string): Promise<void> {
    console.log(`Calculating topic mastery for user ${userId} after attempt ${attemptId}...`);

    try {
      // Get all answers from this attempt with their topics
      const answers = await db
        .select({
          topicId: questionBankItems.topicId,
          isCorrect: attemptAnswers.isCorrect,
          score: attemptAnswers.score,
          maxScore: attemptAnswers.maxScore,
        })
        .from(attemptAnswers)
        .innerJoin(questionBankItems, eq(attemptAnswers.questionBankItemId, questionBankItems.id))
        .where(eq(attemptAnswers.attemptId, attemptId));

      // Group by topic
      const topicStats: Map<
        number,
        {
          totalQuestions: number;
          correctAnswers: number;
          totalScore: number;
          maxScore: number;
        }
      > = new Map();

      for (const answer of answers) {
        if (!answer.topicId) continue; // Skip questions without topics

        const stats = topicStats.get(answer.topicId) || {
          totalQuestions: 0,
          correctAnswers: 0,
          totalScore: 0,
          maxScore: 0,
        };

        stats.totalQuestions++;
        if (answer.isCorrect) stats.correctAnswers++;
        stats.totalScore += answer.score || 0;
        stats.maxScore += answer.maxScore || 0;

        topicStats.set(answer.topicId, stats);
      }

      // Update mastery for each topic
      for (const [topicId, stats] of topicStats) {
        await this.updateTopicMastery(userId, topicId);
      }

      console.log(`Updated mastery for ${topicStats.size} topics`);
    } catch (error) {
      console.error("Error updating topic mastery:", error);
      throw error;
    }
  }

  /**
   * Recalculate and update mastery for a specific user-topic combination
   * @param userId - The user's ID
   * @param topicId - The topic ID
   */
  async updateTopicMastery(userId: string, topicId: number): Promise<void> {
    try {
      // Aggregate all historical data for this user-topic pair
      const results = await db
        .select({
          totalQuestions: sql<number>`CAST(COUNT(*) AS INTEGER)`,
          correctAnswers: sql<number>`CAST(SUM(CASE WHEN ${attemptAnswers.isCorrect} THEN 1 ELSE 0 END) AS INTEGER)`,
          lastAttemptAt: sql<Date>`MAX(${attemptAnswers.answeredAt})`,
        })
        .from(attemptAnswers)
        .innerJoin(questionBankItems, eq(attemptAnswers.questionBankItemId, questionBankItems.id))
        .where(
          and(
            sql`${attemptAnswers.attemptId} IN (
              SELECT id FROM assessment_attempts WHERE user_id = ${userId}
            )`,
            eq(questionBankItems.topicId, topicId)
          )
        );

      const result = results[0];

      if (!result || result.totalQuestions === 0) {
        // No data yet, skip
        return;
      }

      const masteryPercent = Math.round((result.correctAnswers / result.totalQuestions) * 100);

      // Upsert into topic_mastery table
      await db
        .insert(topicMastery)
        .values({
          userId,
          topicId,
          totalQuestions: result.totalQuestions,
          correctAnswers: result.correctAnswers,
          masteryPercent,
          lastAttemptAt: result.lastAttemptAt,
          updatedAt: new Date(),
        })
        .onConflictDoUpdate({
          target: [topicMastery.userId, topicMastery.topicId],
          set: {
            totalQuestions: result.totalQuestions,
            correctAnswers: result.correctAnswers,
            masteryPercent,
            lastAttemptAt: result.lastAttemptAt,
            updatedAt: new Date(),
          },
        });

      console.log(
        `   Topic ${topicId}: ${result.correctAnswers}/${result.totalQuestions} = ${masteryPercent}% mastery`
      );
    } catch (error) {
      console.error(`Error updating mastery for topic ${topicId}:`, error);
      throw error;
    }
  }

  /**
   * Get mastery breakdown for a user across all topics
   */
  async getUserMastery(userId: string, subjectId?: number) {
    try {
      let query = db
        .select({
          topicId: topicMastery.topicId,
          topicTitle: sql<string>`topics.title`,
          subjectId: sql<number>`topics.subject_id`,
          subjectName: sql<string>`subjects.name`,
          totalQuestions: topicMastery.totalQuestions,
          correctAnswers: topicMastery.correctAnswers,
          masteryPercent: topicMastery.masteryPercent,
          lastAttemptAt: topicMastery.lastAttemptAt,
        })
        .from(topicMastery)
        .innerJoin(sql`topics`, eq(topicMastery.topicId, sql`topics.id`))
        .innerJoin(sql`subjects`, eq(sql`topics.subject_id`, sql`subjects.id`))
        .where(eq(topicMastery.userId, userId))
        .$dynamic();

      if (subjectId) {
        query = query.where(eq(sql`topics.subject_id`, subjectId));
      }

      const results = await query;

      return results.sort((a, b) => a.masteryPercent - b.masteryPercent); // Weakest topics first
    } catch (error) {
      console.error("Error fetching user mastery:", error);
      throw error;
    }
  }

  /**
   * Get weakest topics for a user (lowest mastery %)
   */
  async getWeakestTopics(userId: string, limit = 5, minQuestions = 3) {
    try {
      const results = await db
        .select({
          topicId: topicMastery.topicId,
          topicTitle: sql<string>`topics.title`,
          masteryPercent: topicMastery.masteryPercent,
          totalQuestions: topicMastery.totalQuestions,
          correctAnswers: topicMastery.correctAnswers,
        })
        .from(topicMastery)
        .innerJoin(sql`topics`, eq(topicMastery.topicId, sql`topics.id`))
        .where(
          and(
            eq(topicMastery.userId, userId),
            sql`${topicMastery.totalQuestions} >= ${minQuestions}`
          )
        )
        .orderBy(topicMastery.masteryPercent)
        .limit(limit);

      return results;
    } catch (error) {
      console.error("Error fetching weakest topics:", error);
      throw error;
    }
  }

  /**
   * Get strongest topics for a user (highest mastery %)
   */
  async getStrongestTopics(userId: string, limit = 5, minQuestions = 3) {
    try {
      const results = await db
        .select({
          topicId: topicMastery.topicId,
          topicTitle: sql<string>`topics.title`,
          masteryPercent: topicMastery.masteryPercent,
          totalQuestions: topicMastery.totalQuestions,
          correctAnswers: topicMastery.correctAnswers,
        })
        .from(topicMastery)
        .innerJoin(sql`topics`, eq(topicMastery.topicId, sql`topics.id`))
        .where(
          and(
            eq(topicMastery.userId, userId),
            sql`${topicMastery.totalQuestions} >= ${minQuestions}`
          )
        )
        .orderBy(sql`${topicMastery.masteryPercent} DESC`)
        .limit(limit);

      return results;
    } catch (error) {
      console.error("Error fetching strongest topics:", error);
      throw error;
    }
  }

  /**
   * Get overall mastery percentage for a user across all subjects
   */
  async getOverallMastery(userId: string): Promise<number> {
    try {
      const result = await db
        .select({
          totalQuestions: sql<number>`CAST(SUM(total_questions) AS INTEGER)`,
          correctAnswers: sql<number>`CAST(SUM(correct_answers) AS INTEGER)`,
        })
        .from(topicMastery)
        .where(eq(topicMastery.userId, userId));

      const data = result[0];

      if (!data || data.totalQuestions === 0) {
        return 0;
      }

      return Math.round((data.correctAnswers / data.totalQuestions) * 100);
    } catch (error) {
      console.error("Error calculating overall mastery:", error);
      throw error;
    }
  }
}

export const masteryService = new MasteryService();
