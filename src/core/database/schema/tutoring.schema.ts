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
import { tutoringSessionStatusEnum } from "./enums.js";
import { users } from "./users.schema.js";
import { subjects, modules } from "./content.schema.js";

/**
 * Tutoring Schema
 * Tutor profiles, expertise, sessions, feedback, and relationships
 */

// ── TUTOR PROFILES ──────────────────────────

export const tutorProfiles = pgTable("tutor_profiles", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull().unique(),
  bio: text("bio"),
  qualifications: jsonb("qualifications").$type<string[]>().default([]),
  specializations: jsonb("specializations").$type<string[]>().default([]),
  hourlyRate: integer("hourly_rate"),
  availability: jsonb("availability").$type<Record<string, { start: string; end: string }[]>>().default({}),
  rating: integer("rating").default(0),
  totalSessions: integer("total_sessions").default(0).notNull(),
  isActive: boolean("is_active").default(true).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── TUTOR SUBJECT EXPERTISE ─────────────────

export const tutorSubjectExpertise = pgTable("tutor_subject_expertise", {
  id: serial("id").primaryKey(),
  tutorId: integer("tutor_id").references(() => tutorProfiles.id).notNull(),
  subjectId: integer("subject_id").references(() => subjects.id).notNull(),
  gradeMin: integer("grade_min").notNull(),
  gradeMax: integer("grade_max").notNull(),
  yearsExperience: integer("years_experience").default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── TUTORING SESSIONS ───────────────────────

export const tutoringSessions = pgTable("tutoring_sessions", {
  id: serial("id").primaryKey(),
  tutorId: integer("tutor_id").references(() => tutorProfiles.id).notNull(),
  studentId: text("student_id").references(() => users.id).notNull(),
  subjectId: integer("subject_id").references(() => subjects.id),
  moduleId: integer("module_id").references(() => modules.id),
  title: varchar("title", { length: 200 }).notNull(),
  description: text("description"),
  scheduledStart: timestamp("scheduled_start", { withTimezone: true }).notNull(),
  scheduledEnd: timestamp("scheduled_end", { withTimezone: true }).notNull(),
  actualStart: timestamp("actual_start", { withTimezone: true }),
  actualEnd: timestamp("actual_end", { withTimezone: true }),
  status: tutoringSessionStatusEnum("status").default("scheduled").notNull(),
  meetingLink: text("meeting_link"),
  location: text("location"),
  notes: text("notes"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── SESSION FEEDBACK ────────────────────────

export const sessionFeedback = pgTable("session_feedback", {
  id: serial("id").primaryKey(),
  sessionId: integer("session_id").references(() => tutoringSessions.id).notNull(),
  fromUserId: text("from_user_id").references(() => users.id).notNull(),
  toUserId: text("to_user_id").references(() => users.id).notNull(),
  rating: integer("rating").notNull(),
  comment: text("comment"),
  isPublic: boolean("is_public").default(false).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── TUTOR-STUDENT RELATIONSHIPS ─────────────

export const tutorStudentRelationships = pgTable("tutor_student_relationships", {
  id: serial("id").primaryKey(),
  tutorId: integer("tutor_id").references(() => tutorProfiles.id).notNull(),
  studentId: text("student_id").references(() => users.id).notNull(),
  status: varchar("status", { length: 40 }).default("active").notNull(),
  startedAt: timestamp("started_at", { withTimezone: true }).defaultNow().notNull(),
  endedAt: timestamp("ended_at", { withTimezone: true }),
  notes: text("notes"),
});
