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
import { users } from "./users.schema.js";
import type { DashboardLayoutItem, WidgetSettings } from "./types.js";

/**
 * User Preferences Schema
 * Dashboard layouts, accessibility settings, and user preferences
 */

// ── USER PREFERENCES (Dashboard Layout) ─────

export const userPreferences = pgTable("user_preferences", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull().unique(),
  dashboardLayout: jsonb("dashboard_layout").$type<DashboardLayoutItem[]>(),
  widgetSettings: jsonb("widget_settings").$type<WidgetSettings>(),
  themeMode: varchar("theme_mode", { length: 10 }).default("dark"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── ACCESSIBILITY PREFERENCES ───────────────

export const accessibilityPreferences = pgTable("accessibility_preferences", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id).notNull(),
  textScale: integer("text_scale").default(100).notNull(),
  enableNarration: boolean("enable_narration").default(false).notNull(),
  highContrast: boolean("high_contrast").default(false).notNull(),
  language: varchar("language", { length: 12 }).default("en").notNull(),
  translationEnabled: boolean("translation_enabled").default(false).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});
