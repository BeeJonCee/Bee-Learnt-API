/**
 * Neon Auth Schema Mappings
 *
 * These tables are in the neondb database (auto-created by Neon).
 * They are managed by Neon Auth and should be treated as read-only
 * from the application perspective.
 *
 * Connection: neondb (separate from beelearnt database)
 * Schema: neon_auth (Neon Auth creates tables in the "neon_auth" schema)
 */

import { pgSchema, uuid, text, timestamp, boolean, jsonb } from "drizzle-orm/pg-core";

const neonAuth = pgSchema("neon_auth");

// ============ CORE USER TABLE ============

export const neonAuthUsers = neonAuth.table("user", {
  id: uuid("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("emailVerified").default(false),
  image: text("image"),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updatedAt", { withTimezone: true }).notNull(),
  role: text("role"), // STUDENT, PARENT, ADMIN, TUTOR
  banned: boolean("banned").default(false),
  banReason: text("banReason"),
  banExpires: timestamp("banExpires", { withTimezone: true }),
});

// ============ AUTHENTICATION TABLES ============

export const neonAuthAccounts = neonAuth.table("account", {
  id: uuid("id").primaryKey(),
  accountId: text("accountId").notNull(),
  providerId: text("providerId").notNull(),
  userId: uuid("userId").notNull().references(() => neonAuthUsers.id),
  accessToken: text("accessToken"),
  refreshToken: text("refreshToken"),
  idToken: text("idToken"),
  accessTokenExpiresAt: timestamp("accessTokenExpiresAt", { withTimezone: true }),
  refreshTokenExpiresAt: timestamp("refreshTokenExpiresAt", { withTimezone: true }),
  scope: text("scope"),
  password: text("password"),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updatedAt", { withTimezone: true }).notNull(),
});

export const neonAuthSessions = neonAuth.table("session", {
  id: uuid("id").primaryKey(),
  expiresAt: timestamp("expiresAt", { withTimezone: true }).notNull(),
  token: text("token").notNull().unique(),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updatedAt", { withTimezone: true }).notNull(),
  ipAddress: text("ipAddress"),
  userAgent: text("userAgent"),
  userId: uuid("userId").notNull().references(() => neonAuthUsers.id),
  impersonatedBy: text("impersonatedBy"),
  activeOrganizationId: text("activeOrganizationId"),
});

// ============ ORGANIZATION TABLES ============

export const neonAuthOrganizations = neonAuth.table("organization", {
  id: uuid("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  logo: text("logo"),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
  metadata: text("metadata"),
});

export const neonAuthMembers = neonAuth.table("member", {
  id: uuid("id").primaryKey(),
  organizationId: uuid("organizationId").notNull().references(() => neonAuthOrganizations.id),
  userId: uuid("userId").notNull().references(() => neonAuthUsers.id),
  role: text("role").notNull(),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
});

export const neonAuthInvitations = neonAuth.table("invitation", {
  id: uuid("id").primaryKey(),
  organizationId: uuid("organizationId").notNull().references(() => neonAuthOrganizations.id),
  email: text("email").notNull(),
  role: text("role").notNull(),
  status: text("status").notNull(),
  expiresAt: timestamp("expiresAt", { withTimezone: true }).notNull(),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
  inviterId: uuid("inviterId").references(() => neonAuthUsers.id),
});

// ============ VERIFICATION & SECURITY ============

export const neonAuthVerifications = neonAuth.table("verification", {
  id: uuid("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: timestamp("expiresAt", { withTimezone: true }).notNull(),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updatedAt", { withTimezone: true }).notNull(),
});

export const neonAuthJWKS = neonAuth.table("jwks", {
  id: uuid("id").primaryKey(),
  publicKey: text("publicKey").notNull(),
  privateKey: text("privateKey").notNull(),
  createdAt: timestamp("createdAt", { withTimezone: true }).notNull(),
  expiresAt: timestamp("expiresAt", { withTimezone: true }),
});

// ============ PROJECT CONFIGURATION ============

export const neonAuthProjectConfig = neonAuth.table("project_config", {
  id: uuid("id").primaryKey(),
  name: text("name").notNull(),
  endpointId: text("endpoint_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
  trustedOrigins: jsonb("trusted_origins"),
  socialProviders: jsonb("social_providers"),
  emailProvider: jsonb("email_provider"),
  emailAndPassword: jsonb("email_and_password"),
  allowLocalhost: boolean("allow_localhost").default(false),
});

// ============ TYPE EXPORTS ============

export type NeonAuthUser = typeof neonAuthUsers.$inferSelect;
export type NeonAuthAccount = typeof neonAuthAccounts.$inferSelect;
export type NeonAuthSession = typeof neonAuthSessions.$inferSelect;
export type NeonAuthOrganization = typeof neonAuthOrganizations.$inferSelect;
export type NeonAuthMember = typeof neonAuthMembers.$inferSelect;
export type NeonAuthInvitation = typeof neonAuthInvitations.$inferSelect;
export type NeonAuthVerification = typeof neonAuthVerifications.$inferSelect;
export type NeonAuthJWKS = typeof neonAuthJWKS.$inferSelect;
export type NeonAuthProjectConfig = typeof neonAuthProjectConfig.$inferSelect;
