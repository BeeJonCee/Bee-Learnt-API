import {
  boolean,
  integer,
  pgTable,
  serial,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/pg-core";
import { dayOfWeekEnum } from "./enums.js";
import { users } from "./users.schema.js";
import { subjects } from "./content.schema.js";

/**
 * Social & Communication Schema
 * Direct messaging and timetable/schedule
 */

// ── DIRECT MESSAGING ────────────────────────

export const directMessages = pgTable("direct_messages", {
  id: serial("id").primaryKey(),
  senderId: text("sender_id").references(() => users.id).notNull(),
  recipientId: text("recipient_id").references(() => users.id).notNull(),
  subject: varchar("subject", { length: 200 }),
  content: text("content").notNull(),
  readAt: timestamp("read_at", { withTimezone: true }),
  deletedBySender: boolean("deleted_by_sender").default(false).notNull(),
  deletedByRecipient: boolean("deleted_by_recipient").default(false).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── TIMETABLE / SCHEDULE ────────────────────

export const timetableEntries = pgTable("timetable_entries", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  subjectId: integer("subject_id").references(() => subjects.id),
  title: varchar("title", { length: 160 }).notNull(),
  dayOfWeek: dayOfWeekEnum("day_of_week").notNull(),
  startTime: varchar("start_time", { length: 5 }).notNull(),
  endTime: varchar("end_time", { length: 5 }).notNull(),
  location: varchar("location", { length: 120 }),
  color: varchar("color", { length: 7 }),
  isRecurring: boolean("is_recurring").default(true).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});
