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
  lessonTypeEnum,
  resourceTypeEnum,
  assignmentPriorityEnum,
  assignmentStatusEnum,
  moduleAccessStatusEnum,
} from "./enums.js";
import { users } from "./users.schema.js";
import { curricula, topics } from "./curriculum.schema.js";

/**
 * Content Management Schema
 * Tables for subjects, modules, lessons, resources, and assignments
 */

// ── SUBJECTS ────────────────────────────────

export const subjects = pgTable("subjects", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 120 }).notNull(),
  description: text("description"),
  minGrade: integer("min_grade").notNull(),
  maxGrade: integer("max_grade").notNull(),
  code: varchar("code", { length: 20 }),
  capsDocumentUrl: text("caps_document_url"),
  curriculumId: integer("curriculum_id").references(() => curricula.id),
  iconUrl: text("icon_url"),
  color: varchar("color", { length: 7 }),
  isActive: boolean("is_active").default(true).notNull(),
  deletedAt: timestamp("deleted_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── MODULES ─────────────────────────────────

export const modules = pgTable("modules", {
  id: serial("id").primaryKey(),
  subjectId: integer("subject_id").references(() => subjects.id).notNull(),
  title: varchar("title", { length: 160 }).notNull(),
  description: text("description"),
  grade: integer("grade").notNull(),
  order: integer("order").notNull(),
  capsTags: jsonb("caps_tags").$type<string[]>().default([]),
  termNumber: integer("term_number"),
  topicId: integer("topic_id").references(() => topics.id),
  estimatedMinutes: integer("estimated_minutes"),
  prerequisiteModuleId: integer("prerequisite_module_id"),
  isActive: boolean("is_active").default(true).notNull(),
  deletedAt: timestamp("deleted_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── MODULE ACCESS CODES ─────────────────────

export const moduleAccessCodes = pgTable("module_access_codes", {
  id: serial("id").primaryKey(),
  moduleId: integer("module_id").references(() => modules.id).notNull(),
  codeHash: text("code_hash").notNull(),
  active: boolean("active").default(true).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── USER MODULE SELECTIONS ──────────────────

export const userModuleSelections = pgTable("user_module_selections", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  moduleId: integer("module_id").references(() => modules.id).notNull(),
  status: moduleAccessStatusEnum("status").default("pending").notNull(),
  selectedAt: timestamp("selected_at", { withTimezone: true }).defaultNow().notNull(),
  unlockedAt: timestamp("unlocked_at", { withTimezone: true }),
});

// ── LESSONS ─────────────────────────────────

export const lessons = pgTable("lessons", {
  id: serial("id").primaryKey(),
  moduleId: integer("module_id").references(() => modules.id).notNull(),
  title: varchar("title", { length: 160 }).notNull(),
  content: text("content"),
  type: lessonTypeEnum("type").notNull(),
  videoUrl: text("video_url"),
  diagramUrl: text("diagram_url"),
  pdfUrl: text("pdf_url"),
  order: integer("order").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── LESSON NOTES ────────────────────────────

export const lessonNotes = pgTable("lesson_notes", {
  id: serial("id").primaryKey(),
  lessonId: integer("lesson_id").references(() => lessons.id).notNull(),
  userId: text("user_id").references(() => users.id).notNull(),
  content: text("content").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── LESSON RESOURCES ────────────────────────

export const lessonResources = pgTable("lesson_resources", {
  id: serial("id").primaryKey(),
  lessonId: integer("lesson_id").references(() => lessons.id).notNull(),
  title: varchar("title", { length: 160 }).notNull(),
  type: resourceTypeEnum("type").notNull(),
  url: text("url").notNull(),
  tags: jsonb("tags").$type<string[]>().default([]),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── ASSIGNMENTS ─────────────────────────────

export const assignments = pgTable("assignments", {
  id: serial("id").primaryKey(),
  moduleId: integer("module_id").references(() => modules.id).notNull(),
  lessonId: integer("lesson_id").references(() => lessons.id),
  title: varchar("title", { length: 160 }).notNull(),
  description: text("description"),
  dueDate: timestamp("due_date", { withTimezone: true }).notNull(),
  priority: assignmentPriorityEnum("priority").default("medium").notNull(),
  status: assignmentStatusEnum("status").default("todo").notNull(),
  grade: integer("grade").notNull(),
  reminders: jsonb("reminders").$type<string[]>().default([]),
  createdBy: text("created_by").references(() => users.id),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── MODULE CHECKLIST ────────────────────────

export const moduleChecklistItems = pgTable("module_checklist_items", {
  id: serial("id").primaryKey(),
  moduleId: integer("module_id").references(() => modules.id).notNull(),
  title: varchar("title", { length: 160 }).notNull(),
  order: integer("order").notNull(),
  required: boolean("required").default(true).notNull(),
});

export const checklistProgress = pgTable("checklist_progress", {
  id: serial("id").primaryKey(),
  itemId: integer("item_id").references(() => moduleChecklistItems.id).notNull(),
  userId: text("user_id").references(() => users.id).notNull(),
  completed: boolean("completed").default(false).notNull(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
});
