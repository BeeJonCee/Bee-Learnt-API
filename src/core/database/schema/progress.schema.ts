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
  learningPaceEnum,
  learningPathStatusEnum,
  quizDifficultyEnum,
} from "./enums.js";
import { users } from "./users.schema.js";
import { lessons, modules } from "./content.schema.js";
import { topics } from "./curriculum.schema.js";

/**
 * Progress Tracking Schema
 * User progress, topic mastery, learning profiles, and learning paths
 */

// ── PROGRESS TRACKING ───────────────────────

export const progressTracking = pgTable("progress_tracking", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  lessonId: integer("lesson_id").references(() => lessons.id),
  moduleId: integer("module_id").references(() => modules.id),
  completed: boolean("completed").default(false).notNull(),
  timeSpentMinutes: integer("time_spent_minutes").default(0).notNull(),
  lastAccessedAt: timestamp("last_accessed_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── TOPIC MASTERY ───────────────────────────

export const topicMastery = pgTable("topic_mastery", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  topicId: integer("topic_id").references(() => topics.id).notNull(),
  totalQuestions: integer("total_questions").default(0).notNull(),
  correctAnswers: integer("correct_answers").default(0).notNull(),
  masteryPercent: integer("mastery_percent").default(0).notNull(),
  lastAttemptAt: timestamp("last_attempt_at", { withTimezone: true }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── LEARNING PROFILES ───────────────────────

export const learningProfiles = pgTable("learning_profiles", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  strengths: jsonb("strengths").$type<string[]>().default([]),
  weaknesses: jsonb("weaknesses").$type<string[]>().default([]),
  goals: jsonb("goals").$type<string[]>().default([]),
  preferredPace: learningPaceEnum("preferred_pace").default("steady").notNull(),
  recommendedDifficulty: quizDifficultyEnum("recommended_difficulty")
    .default("medium")
    .notNull(),
  lastAdaptiveUpdateAt: timestamp("last_adaptive_update_at", { withTimezone: true }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── LEARNING PATH ITEMS ─────────────────────

export const learningPathItems = pgTable("learning_path_items", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  moduleId: integer("module_id").references(() => modules.id),
  lessonId: integer("lesson_id").references(() => lessons.id),
  title: varchar("title", { length: 180 }).notNull(),
  reason: text("reason"),
  priority: integer("priority").default(1).notNull(),
  status: learningPathStatusEnum("status").default("active").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});
