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
  badgeRuleEnum,
  studyGoalStatusEnum,
  studyGoalPriorityEnum,
  challengeTypeEnum,
  challengeStatusEnum,
} from "./enums.js";
import { users } from "./users.schema.js";

/**
 * Gamification Schema
 * Badges, points, challenges, streaks, study sessions, and goals
 */

// ── BADGES ──────────────────────────────────

export const badges = pgTable("badges", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 120 }).notNull(),
  description: text("description"),
  ruleKey: badgeRuleEnum("rule_key").notNull(),
  criteria: jsonb("criteria").$type<Record<string, unknown>>().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const userBadges = pgTable("user_badges", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  badgeId: integer("badge_id").references(() => badges.id).notNull(),
  awardedAt: timestamp("awarded_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── USER POINTS / XP SYSTEM ─────────────────

export const userPoints = pgTable("user_points", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull().unique(),
  totalXp: integer("total_xp").default(0).notNull(),
  level: integer("level").default(1).notNull(),
  weeklyXp: integer("weekly_xp").default(0).notNull(),
  monthlyXp: integer("monthly_xp").default(0).notNull(),
  lastXpAwardedAt: timestamp("last_xp_awarded_at", { withTimezone: true }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── CHALLENGES ──────────────────────────────

export const challenges = pgTable("challenges", {
  id: serial("id").primaryKey(),
  title: varchar("title", { length: 200 }).notNull(),
  description: text("description"),
  type: challengeTypeEnum("type").notNull(),
  xpReward: integer("xp_reward").notNull(),
  targetValue: integer("target_value").notNull(),
  metricKey: varchar("metric_key", { length: 80 }).notNull(),
  startsAt: timestamp("starts_at", { withTimezone: true }),
  endsAt: timestamp("ends_at", { withTimezone: true }),
  isActive: boolean("is_active").default(true).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const userChallenges = pgTable("user_challenges", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  challengeId: integer("challenge_id").references(() => challenges.id).notNull(),
  currentValue: integer("current_value").default(0).notNull(),
  status: challengeStatusEnum("status").default("active").notNull(),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  startedAt: timestamp("started_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── STREAKS ─────────────────────────────────

export const streaks = pgTable("streaks", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  currentStreak: integer("current_streak").default(0).notNull(),
  longestStreak: integer("longest_streak").default(0).notNull(),
  lastStudyDate: timestamp("last_study_date", { withTimezone: true }),
  weeklyMinutes: integer("weekly_minutes").default(0).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── STUDY SESSIONS ──────────────────────────

export const studySessions = pgTable("study_sessions", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  startedAt: timestamp("started_at", { withTimezone: true }).notNull(),
  endedAt: timestamp("ended_at", { withTimezone: true }),
  durationMinutes: integer("duration_minutes").default(0).notNull(),
  source: varchar("source", { length: 40 }).default("timer").notNull(),
});

// ── STUDY GOALS ─────────────────────────────

export const studyGoals = pgTable("study_goals", {
  id: varchar("id", { length: 64 }).primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  targetHours: integer("target_hours").notNull(),
  currentHours: integer("current_hours").default(0).notNull(),
  deadline: timestamp("deadline", { withTimezone: true }).notNull(),
  status: studyGoalStatusEnum("status").default("active").notNull(),
  priority: studyGoalPriorityEnum("priority").default("medium").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});
