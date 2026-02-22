import {
  integer,
  jsonb,
  pgTable,
  serial,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import type { RubricScore } from "./types.js";
import { users } from "./users.schema.js";
import { assignments } from "./content.schema.js";
import { rubrics } from "./rubrics.schema.js";

/**
 * Assignment Submissions & Grading Schema
 */

export const assignmentSubmissions = pgTable(
  "assignment_submissions",
  {
    id: serial("id").primaryKey(),
    assignmentId: integer("assignment_id")
      .references(() => assignments.id)
      .notNull(),
    userId: text("user_id")
      .references(() => users.id)
      .notNull(),
    submissionText: text("submission_text"),
    submittedAt: timestamp("submitted_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    // Grading (filled in by tutor/admin)
    rubricId: integer("rubric_id").references(() => rubrics.id),
    rubricScores: jsonb("rubric_scores").$type<RubricScore[]>(),
    totalScore: integer("total_score"),
    maxScore: integer("max_score"),
    feedback: text("feedback"),
    gradedAt: timestamp("graded_at", { withTimezone: true }),
    gradedBy: text("graded_by").references(() => users.id),
  },
  (t) => [uniqueIndex("assignment_submissions_user_idx").on(t.assignmentId, t.userId)],
);
