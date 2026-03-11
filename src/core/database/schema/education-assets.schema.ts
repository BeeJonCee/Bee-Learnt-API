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
  educationAssetCategoryEnum,
  educationAssetKindEnum,
  educationAssetLinkRoleEnum,
  examSessionEnum,
} from "./enums.js";
import { subjects, modules, lessons } from "./content.schema.js";
import { grades } from "./curriculum.schema.js";

/**
 * Education Assets Schema
 * Canonical catalog of files discovered in api/src/Education.
 */

export const educationChapters = pgTable("education_chapters", {
  id: serial("id").primaryKey(),
  subjectId: integer("subject_id").references(() => subjects.id).notNull(),
  gradeId: integer("grade_id").references(() => grades.id),
  chapterNumber: integer("chapter_number").notNull(),
  title: varchar("title", { length: 200 }).notNull(),
  summary: text("summary"),
  order: integer("order").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export const educationAssets = pgTable("education_assets", {
  id: serial("id").primaryKey(),
  subjectId: integer("subject_id").references(() => subjects.id).notNull(),
  gradeId: integer("grade_id").references(() => grades.id),
  chapterId: integer("chapter_id").references(() => educationChapters.id),
  kind: educationAssetKindEnum("kind").notNull(),
  category: educationAssetCategoryEnum("category").notNull(),
  sourceRelPath: text("source_rel_path").notNull(),
  sourceAbsPath: text("source_abs_path"),
  title: varchar("title", { length: 300 }).notNull(),
  mimeType: varchar("mime_type", { length: 60 }),
  fileSize: integer("file_size"),
  language: varchar("language", { length: 20 }).default("English").notNull(),
  year: integer("year"),
  session: examSessionEnum("session"),
  paperNumber: integer("paper_number"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().default({}),
  isAvailable: boolean("is_available").default(true).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export const educationAssetLinks = pgTable("education_asset_links", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").references(() => educationAssets.id).notNull(),
  chapterId: integer("chapter_id").references(() => educationChapters.id),
  moduleId: integer("module_id").references(() => modules.id),
  lessonId: integer("lesson_id").references(() => lessons.id),
  role: educationAssetLinkRoleEnum("role").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});
