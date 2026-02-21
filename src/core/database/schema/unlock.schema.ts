import {
  boolean,
  integer,
  pgTable,
  serial,
  text,
  timestamp,
} from "drizzle-orm/pg-core";
import { moduleAssignmentStatusEnum } from "./enums.js";
import { users } from "./users.schema.js";
import { modules } from "./content.schema.js";

/**
 * Module Assignment & Unlock System Schema
 * Module assignments, daily tokens, and token attempts
 */

// ── MODULE ASSIGNMENTS ──────────────────────

export const moduleAssignments = pgTable("module_assignments", {
  id: serial("id").primaryKey(),
  studentId: text("student_id").references(() => users.id).notNull(),
  moduleId: integer("module_id").references(() => modules.id).notNull(),
  assignedBy: text("assigned_by").references(() => users.id).notNull(),
  status: moduleAssignmentStatusEnum("status").default("assigned").notNull(),
  dueDate: timestamp("due_date", { withTimezone: true }),
  unlockedAt: timestamp("unlocked_at", { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  assignedAt: timestamp("assigned_at", { withTimezone: true }).defaultNow().notNull(),
  notes: text("notes"),
});

// ── DAILY MODULE TOKENS ─────────────────────

export const dailyModuleTokens = pgTable("daily_module_tokens", {
  id: serial("id").primaryKey(),
  moduleId: integer("module_id").references(() => modules.id).notNull(),
  date: timestamp("date", { withTimezone: true }).notNull(),
  tokenHash: text("token_hash").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdBy: text("created_by").references(() => users.id).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  emailedAt: timestamp("emailed_at", { withTimezone: true }),
});

// ── TOKEN ATTEMPTS ──────────────────────────

export const tokenAttempts = pgTable("token_attempts", {
  id: serial("id").primaryKey(),
  studentId: text("student_id").references(() => users.id).notNull(),
  moduleId: integer("module_id").references(() => modules.id).notNull(),
  tokenId: integer("token_id").references(() => dailyModuleTokens.id),
  date: timestamp("date", { withTimezone: true }).notNull(),
  attemptToken: text("attempt_token").notNull(),
  success: boolean("success").notNull(),
  attemptsCount: integer("attempts_count").default(1).notNull(),
  lockedUntil: timestamp("locked_until", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});
