import {
  boolean,
  integer,
  pgTable,
  serial,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/pg-core";
import { subjects } from "./content.schema.js";

/**
 * Curriculum Hierarchy Schema
 * Tables for curricula, grades, topics, and learning outcomes
 */

// ── CURRICULA ───────────────────────────────

export const curricula = pgTable("curricula", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 120 }).notNull(),
  country: varchar("country", { length: 60 }).notNull(),
  description: text("description"),
  isActive: boolean("is_active").default(true).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── GRADES ──────────────────────────────────

export const grades = pgTable("grades", {
  id: serial("id").primaryKey(),
  curriculumId: integer("curriculum_id").references(() => curricula.id).notNull(),
  level: integer("level").notNull(),
  label: varchar("label", { length: 40 }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── TOPICS ──────────────────────────────────

export const topics = pgTable("topics", {
  id: serial("id").primaryKey(),
  subjectId: integer("subject_id").references(() => subjects.id).notNull(),
  gradeId: integer("grade_id").references(() => grades.id).notNull(),
  parentTopicId: integer("parent_topic_id"),
  title: varchar("title", { length: 200 }).notNull(),
  description: text("description"),
  termNumber: integer("term_number"),
  capsReference: varchar("caps_reference", { length: 80 }),
  order: integer("order").notNull().default(0),
  weighting: integer("weighting"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── LEARNING OUTCOMES ───────────────────────

export const learningOutcomes = pgTable("learning_outcomes", {
  id: serial("id").primaryKey(),
  topicId: integer("topic_id").references(() => topics.id).notNull(),
  code: varchar("code", { length: 40 }),
  description: text("description").notNull(),
  bloomsLevel: varchar("blooms_level", { length: 20 }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});
