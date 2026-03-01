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
import { roleEnum } from "./enums.js";

/**
 * User Management Schema
 * Tables for user profiles, roles, and parent-student relationships
 */

// ── ROLES ───────────────────────────────────

export const roles = pgTable("roles", {
  id: serial("id").primaryKey(),
  name: roleEnum("name").notNull().unique(),
  description: text("description"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── USERS (PUBLIC SCHEMA) ───────────────────

export const users = pgTable("users", {
  id: text("id").primaryKey(),
  name: varchar("name", { length: 120 }).notNull(),
  email: varchar("email", { length: 255 }).notNull().unique(),
  phone: varchar("phone", { length: 30 }).unique(),
  passwordHash: text("password_hash"),
  image: text("image"),
  roleId: integer("role_id").references(() => roles.id).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  emailVerifiedAt: timestamp("email_verified_at", { withTimezone: true }),
  phoneVerifiedAt: timestamp("phone_verified_at", { withTimezone: true }),
  loginEmailAlertEnabled: boolean("login_email_alert_enabled")
    .default(true)
    .notNull(),
  loginSmsAlertEnabled: boolean("login_sms_alert_enabled")
    .default(false)
    .notNull(),
  lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
});

// One-time codes used for auth verification flows (login/register/social exchange).
export const emailVerificationCodes = pgTable("email_verification_codes", {
  id: serial("id").primaryKey(),
  email: text("email").notNull(),
  codeHash: text("code_hash").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  consumedAt: timestamp("consumed_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// Unified verification table for email + SMS OTP flows.
export const authVerificationCodes = pgTable("auth_verification_codes", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id),
  channel: varchar("channel", { length: 16 }).notNull(), // "email" | "sms"
  purpose: varchar("purpose", { length: 40 }).notNull(), // "email_verification" | "phone_verification"
  target: text("target").notNull(), // normalized email or E.164 phone
  codeHash: text("code_hash").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  attempts: integer("attempts").default(0).notNull(),
  lastSentAt: timestamp("last_sent_at", { withTimezone: true }).defaultNow().notNull(),
  consumedAt: timestamp("consumed_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// Password-reset tokens (1-hour expiry, single-use)
export const passwordResetTokens = pgTable("password_reset_tokens", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  tokenHash: text("token_hash").notNull().unique(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  consumedAt: timestamp("consumed_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── PARENT-STUDENT RELATIONSHIPS ────────────

export const parentStudentLinks = pgTable("parent_student_links", {
  id: serial("id").primaryKey(),
  parentId: text("parent_id").references(() => users.id).notNull(),
  studentId: text("student_id").references(() => users.id).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── USER PROFILES ───────────────────────────

export const studentProfiles = pgTable("student_profiles", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull().unique(),
  grade: integer("grade").notNull(),
  school: varchar("school", { length: 200 }),
  dateOfBirth: timestamp("date_of_birth", { withTimezone: true }),
  guardianName: varchar("guardian_name", { length: 120 }),
  guardianContact: varchar("guardian_contact", { length: 80 }),
  emergencyContact: varchar("emergency_contact", { length: 80 }),
  medicalInfo: text("medical_info"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export const parentProfiles = pgTable("parent_profiles", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull().unique(),
  occupation: varchar("occupation", { length: 120 }),
  phoneNumber: varchar("phone_number", { length: 40 }),
  address: text("address"),
  emergencyContact: varchar("emergency_contact", { length: 80 }),
  preferences: jsonb("preferences").$type<Record<string, unknown>>().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});
