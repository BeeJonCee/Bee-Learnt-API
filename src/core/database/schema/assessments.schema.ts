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
  assessmentTypeEnum,
  assessmentStatusEnum,
  attemptStatusEnum,
} from "./enums.js";
import { users } from "./users.schema.js";
import { subjects, modules } from "./content.schema.js";
import { questionBankItems } from "./questions.schema.js";

/**
 * Assessment Engine Schema
 * Tests, exams, and practice sessions
 */

// ── ASSESSMENTS ─────────────────────────────

export const assessments = pgTable("assessments", {
  id: serial("id").primaryKey(),
  title: varchar("title", { length: 200 }).notNull(),
  description: text("description"),
  type: assessmentTypeEnum("type").notNull(),
  status: assessmentStatusEnum("status").default("draft").notNull(),
  subjectId: integer("subject_id").references(() => subjects.id).notNull(),
  grade: integer("grade"),
  moduleId: integer("module_id").references(() => modules.id),
  timeLimitMinutes: integer("time_limit_minutes"),
  totalMarks: integer("total_marks"),
  passMark: integer("pass_mark"),
  maxAttempts: integer("max_attempts"),
  shuffleQuestions: boolean("shuffle_questions").default(false).notNull(),
  shuffleOptions: boolean("shuffle_options").default(false).notNull(),
  showResultsImmediately: boolean("show_results_immediately").default(true).notNull(),
  showCorrectAnswers: boolean("show_correct_answers").default(true).notNull(),
  showExplanations: boolean("show_explanations").default(true).notNull(),
  availableFrom: timestamp("available_from", { withTimezone: true }),
  availableUntil: timestamp("available_until", { withTimezone: true }),
  instructions: text("instructions"),
  createdBy: text("created_by").references(() => users.id),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── ASSESSMENT SECTIONS ─────────────────────

export const assessmentSections = pgTable("assessment_sections", {
  id: serial("id").primaryKey(),
  assessmentId: integer("assessment_id").references(() => assessments.id).notNull(),
  title: varchar("title", { length: 160 }),
  instructions: text("instructions"),
  order: integer("order").notNull(),
  timeLimitMinutes: integer("time_limit_minutes"),
});

// ── ASSESSMENT QUESTIONS ────────────────────

export const assessmentQuestions = pgTable("assessment_questions", {
  id: serial("id").primaryKey(),
  assessmentId: integer("assessment_id").references(() => assessments.id).notNull(),
  sectionId: integer("section_id").references(() => assessmentSections.id),
  questionBankItemId: integer("question_bank_item_id")
    .references(() => questionBankItems.id)
    .notNull(),
  order: integer("order").notNull(),
  overridePoints: integer("override_points"),
});

// ── ASSESSMENT ATTEMPTS ─────────────────────

export const assessmentAttempts = pgTable("assessment_attempts", {
  id: text("id").primaryKey(),
  assessmentId: integer("assessment_id").references(() => assessments.id).notNull(),
  userId: text("user_id").references(() => users.id).notNull(),
  status: attemptStatusEnum("status").default("in_progress").notNull(),
  startedAt: timestamp("started_at", { withTimezone: true }).defaultNow().notNull(),
  submittedAt: timestamp("submitted_at", { withTimezone: true }),
  totalScore: integer("total_score"),
  maxScore: integer("max_score"),
  percentage: integer("percentage"),
  timeSpentSeconds: integer("time_spent_seconds"),
  feedback: text("feedback"),
  gradedBy: text("graded_by").references(() => users.id),
  gradedAt: timestamp("graded_at", { withTimezone: true }),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── ATTEMPT ANSWERS ─────────────────────────

export const attemptAnswers = pgTable("attempt_answers", {
  id: serial("id").primaryKey(),
  attemptId: text("attempt_id").references(() => assessmentAttempts.id).notNull(),
  assessmentQuestionId: integer("assessment_question_id")
    .references(() => assessmentQuestions.id)
    .notNull(),
  questionBankItemId: integer("question_bank_item_id")
    .references(() => questionBankItems.id)
    .notNull(),
  answer: jsonb("answer").$type<unknown>().default(null),
  isCorrect: boolean("is_correct"),
  score: integer("score"),
  maxScore: integer("max_score"),
  timeTakenSeconds: integer("time_taken_seconds"),
  markerComment: text("marker_comment"),
  answeredAt: timestamp("answered_at", { withTimezone: true }),
});
