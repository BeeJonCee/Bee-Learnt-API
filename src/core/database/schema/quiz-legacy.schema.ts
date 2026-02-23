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
import { quizDifficultyEnum, quizTypeEnum } from "./enums.js";
import { users } from "./users.schema.js";
import { modules } from "./content.schema.js";
import { topics } from "./curriculum.schema.js";
import { questionBankItems } from "./questions.schema.js";

/**
 * Legacy Quiz System Schema
 * Original quiz tables (kept for backward compatibility)
 */

// ── QUIZZES ─────────────────────────────────

export const quizzes = pgTable("quizzes", {
  id: serial("id").primaryKey(),
  moduleId: integer("module_id").references(() => modules.id).notNull(),
  title: varchar("title", { length: 160 }).notNull(),
  description: text("description"),
  difficulty: quizDifficultyEnum("difficulty").default("medium").notNull(),
  source: varchar("source", { length: 40 }).default("manual").notNull(),
  capsTags: jsonb("caps_tags").$type<string[]>().default([]),
  revealCorrectAnswers: boolean("reveal_correct_answers").default(true).notNull(),
  revealToParents: boolean("reveal_to_parents").default(true).notNull(),
  createdBy: text("created_by").references(() => users.id),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── QUIZ QUESTIONS ──────────────────────────

export const quizQuestions = pgTable("quiz_questions", {
  id: serial("id").primaryKey(),
  quizId: integer("quiz_id").references(() => quizzes.id).notNull(),
  type: quizTypeEnum("type").notNull(),
  questionText: text("question_text").notNull(),
  options: jsonb("options").$type<string[] | null>().default(null),
  correctAnswer: text("correct_answer"),
  explanation: text("explanation"),
  points: integer("points").default(1).notNull(),
  difficulty: quizDifficultyEnum("difficulty").default("medium"),
  topicId: integer("topic_id").references(() => topics.id),
  questionBankItemId: integer("question_bank_item_id").references(() => questionBankItems.id),
  tags: jsonb("tags").$type<string[]>().default([]),
  imageUrl: text("image_url"),
  timeLimitSeconds: integer("time_limit_seconds"),
});

// ── QUIZ ATTEMPTS ───────────────────────────

export const quizAttempts = pgTable("quiz_attempts", {
  id: serial("id").primaryKey(),
  quizId: integer("quiz_id").references(() => quizzes.id).notNull(),
  userId: text("user_id").references(() => users.id).notNull(),
  score: integer("score").notNull(),
  maxScore: integer("max_score").notNull(),
  feedback: text("feedback"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── QUIZ ANSWERS ────────────────────────────

export const quizAnswers = pgTable("quiz_answers", {
  id: serial("id").primaryKey(),
  attemptId: integer("attempt_id").references(() => quizAttempts.id).notNull(),
  questionId: integer("question_id").references(() => quizQuestions.id).notNull(),
  answer: text("answer"),
  isCorrect: boolean("is_correct").default(false).notNull(),
  score: integer("score").default(0).notNull(),
});
