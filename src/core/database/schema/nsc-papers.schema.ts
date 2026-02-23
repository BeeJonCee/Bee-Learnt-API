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
import { examSessionEnum, paperDocTypeEnum } from "./enums.js";
import { subjects } from "./content.schema.js";
import { grades, topics } from "./curriculum.schema.js";

/**
 * NSC Past Papers Schema
 * Papers, documents, and extracted questions
 */

// ── NSC PAPERS ──────────────────────────────

export const nscPapers = pgTable("nsc_papers", {
  id: serial("id").primaryKey(),
  subjectId: integer("subject_id").references(() => subjects.id).notNull(),
  gradeId: integer("grade_id").references(() => grades.id),
  year: integer("year").notNull(),
  session: examSessionEnum("session").notNull(),
  paperNumber: integer("paper_number").notNull(),
  language: varchar("language", { length: 20 }).default("English").notNull(),
  totalMarks: integer("total_marks"),
  durationMinutes: integer("duration_minutes"),
  isProcessed: boolean("is_processed").default(false).notNull(),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── NSC PAPER DOCUMENTS ─────────────────────

export const nscPaperDocuments = pgTable("nsc_paper_documents", {
  id: serial("id").primaryKey(),
  nscPaperId: integer("nsc_paper_id").references(() => nscPapers.id).notNull(),
  docType: paperDocTypeEnum("doc_type").notNull(),
  title: varchar("title", { length: 300 }).notNull(),
  fileUrl: text("file_url").notNull(),
  filePath: text("file_path"),
  fileSize: integer("file_size"),
  mimeType: varchar("mime_type", { length: 60 }),
  language: varchar("language", { length: 20 }).default("English").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── NSC PAPER QUESTIONS ─────────────────────

export const nscPaperQuestions = pgTable("nsc_paper_questions", {
  id: serial("id").primaryKey(),
  nscPaperId: integer("nsc_paper_id").references(() => nscPapers.id).notNull(),
  questionNumber: varchar("question_number", { length: 20 }).notNull(),
  questionText: text("question_text").notNull(),
  marks: integer("marks").notNull(),
  topicId: integer("topic_id").references(() => topics.id),
  sectionLabel: varchar("section_label", { length: 60 }),
  imageUrl: text("image_url"),
  memoText: text("memo_text"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});
