import {
  integer,
  jsonb,
  pgTable,
  serial,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/pg-core";
import type { RubricCriterion } from "./types.js";
import { users } from "./users.schema.js";
import { subjects } from "./content.schema.js";

/**
 * Grading Rubrics Schema
 */

export const rubrics = pgTable("rubrics", {
  id: serial("id").primaryKey(),
  title: varchar("title", { length: 200 }).notNull(),
  subjectId: integer("subject_id").references(() => subjects.id),
  criteria: jsonb("criteria").$type<RubricCriterion[]>().notNull(),
  createdBy: text("created_by").references(() => users.id),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});
