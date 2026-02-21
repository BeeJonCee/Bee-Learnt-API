import {
  boolean,
  integer,
  jsonb,
  pgTable,
  serial,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/pg-core";
import {
  quizTypeEnum,
  quizDifficultyEnum,
  questionBankSourceEnum,
} from "./enums.js";
import { users } from "./users.schema.js";
import { subjects, modules } from "./content.schema.js";
import { topics, learningOutcomes } from "./curriculum.schema.js";

/**
 * Question Bank Schema
 * Reusable, taggable, multi-type questions — foundation for assessments
 */

export const questionBankItems = pgTable("question_bank_items", {
  id: serial("id").primaryKey(),
  subjectId: integer("subject_id").references(() => subjects.id).notNull(),
  moduleId: integer("module_id").references(() => modules.id),
  topicId: integer("topic_id").references(() => topics.id),
  learningOutcomeId: integer("learning_outcome_id").references(() => learningOutcomes.id),
  nscPaperQuestionId: integer("nsc_paper_question_id"),
  type: quizTypeEnum("type").notNull(),
  difficulty: quizDifficultyEnum("difficulty").default("medium").notNull(),
  questionText: text("question_text").notNull(),
  questionHtml: text("question_html"),
  imageUrl: text("image_url"),
  options: jsonb("options").$type<unknown>().default(null),
  correctAnswer: jsonb("correct_answer").$type<unknown>().default(null),
  explanation: text("explanation"),
  solutionSteps: jsonb("solution_steps").$type<string[]>().default([]),
  points: integer("points").default(1).notNull(),
  timeLimitSeconds: integer("time_limit_seconds"),
  source: questionBankSourceEnum("source").default("manual").notNull(),
  sourceReference: varchar("source_reference", { length: 200 }),
  tags: jsonb("tags").$type<string[]>().default([]),
  language: varchar("language", { length: 10 }).default("en").notNull(),
  isActive: boolean("is_active").default(true).notNull(),
  createdBy: text("created_by").references(() => users.id),
  reviewedBy: text("reviewed_by").references(() => users.id),
  reviewedAt: timestamp("reviewed_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});
