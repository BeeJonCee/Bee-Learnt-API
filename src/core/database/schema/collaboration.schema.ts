import {
  integer,
  pgTable,
  serial,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/pg-core";
import { collaborationRoomTypeEnum } from "./enums.js";
import { users } from "./users.schema.js";

/**
 * Collaboration Schema
 * Rooms, members, and messages
 */

// ── COLLABORATION ROOMS ─────────────────────

export const collaborationRooms = pgTable("collaboration_rooms", {
  id: serial("id").primaryKey(),
  title: varchar("title", { length: 160 }).notNull(),
  type: collaborationRoomTypeEnum("type").notNull(),
  ownerId: text("owner_id").references(() => users.id).notNull(),
  description: text("description"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── COLLABORATION MEMBERS ───────────────────

export const collaborationMembers = pgTable("collaboration_members", {
  id: serial("id").primaryKey(),
  roomId: integer("room_id").references(() => collaborationRooms.id).notNull(),
  userId: text("user_id").references(() => users.id).notNull(),
  role: varchar("role", { length: 40 }).default("member").notNull(),
  joinedAt: timestamp("joined_at", { withTimezone: true }).defaultNow().notNull(),
});

// ── COLLABORATION MESSAGES ──────────────────

export const collaborationMessages = pgTable("collaboration_messages", {
  id: serial("id").primaryKey(),
  roomId: integer("room_id").references(() => collaborationRooms.id).notNull(),
  userId: text("user_id").references(() => users.id).notNull(),
  content: text("content").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});
