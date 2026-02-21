import {
  integer,
  pgTable,
  serial,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/pg-core";
import { subjectResourceTypeEnum } from "./enums.js";
import { subjects } from "./content.schema.js";
import { grades } from "./curriculum.schema.js";

/**
 * Subject Resources Schema
 * Grade-level resources (textbooks, guides, data files) not tied to a specific lesson
 */

export const subjectResources = pgTable("subject_resources", {
  id: serial("id").primaryKey(),
  subjectId: integer("subject_id")
    .references(() => subjects.id)
    .notNull(),
  gradeId: integer("grade_id").references(() => grades.id),
  title: varchar("title", { length: 300 }).notNull(),
  type: subjectResourceTypeEnum("type").notNull(),
  fileUrl: text("file_url").notNull(),
  filePath: text("file_path"),
  fileSize: integer("file_size"),
  mimeType: varchar("mime_type", { length: 60 }),
  language: varchar("language", { length: 20 }).default("English").notNull(),
  description: text("description"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
});
