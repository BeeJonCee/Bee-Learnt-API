/**
 * Neon Auth Synchronization Service (Consolidated)
 *
 * Two separate databases:
 *   - neondb  (Neon Auth, auto-created) → neon_auth schema
 *     (user, session, member, account, organization, verification, jwks)
 *   - beelearnt (application)           → public schema
 *     (users, roles, profiles, etc.)
 *
 * All neondb auth tables live in the "neon_auth" schema.
 *
 * Role Hierarchy:
 * - ADMIN  → Full platform access
 * - TUTOR  → Can assign modules, manage sessions, view student progress
 * - PARENT → Can view linked children's progress (read-only)
 * - STUDENT → Can view content, take quizzes, track own progress
 *
 * Role Source Priority:
 * 1. neondb.neon_auth.member.role  (when an active organization is known)
 * 2. neondb.neon_auth.user.role
 * 3. Default to STUDENT if no role set
 */

import bcrypt from "bcryptjs";
import { eq, and, sql } from "drizzle-orm";
import { db as appDb } from "../core/database/index.js";
import { db as authDb } from "../core/database/neon-auth-db.js";
import { users, roles } from "../core/database/schema/index.js";
import {
  neonAuthUsers,
  neonAuthAccounts,
  neonAuthSessions,
} from "../core/database/neon-auth-schema.js";
import type { BeeLearntRole } from "../shared/types/auth.js";
import { getUserEffectiveRole } from "./neon-member.service.js";
import { env } from "../config/env.js";

const VALID_ROLES: BeeLearntRole[] = ["STUDENT", "PARENT", "TUTOR", "ADMIN"];
const DEFAULT_ROLE: BeeLearntRole = "STUDENT";

// Error codes for missing tables/schemas in neondb — expected when Neon Auth
// tables haven't been created yet. Return null instead of crashing.
const NEON_AUTH_MISSING_CODES = new Set(["42P01", "3F000"]);

function isNeonAuthMissingError(error: unknown): boolean {
  const code = (error as { code?: string } | null)?.code;
  return !!code && NEON_AUTH_MISSING_CODES.has(code);
}

function ensureAuthDb() {
  if (!authDb) {
    throw new Error("Neon Auth database not configured (NEON_AUTH_DATABASE_URL missing)");
  }
  return authDb;
}

// ─── Public Helpers ──────────────────────────────────────────

/**
 * Check if Neon Auth database is configured and available
 */
export function isNeonAuthAvailable(): boolean {
  return !!env.neonAuthDatabaseUrl;
}

/**
 * Normalize role string to BeeLearntRole
 */
function normalizeRole(role?: string | null): BeeLearntRole {
  if (!role) return DEFAULT_ROLE;

  const upper = role.toUpperCase().trim();

  // Direct match
  if (VALID_ROLES.includes(upper as BeeLearntRole)) {
    return upper as BeeLearntRole;
  }

  // Map common role names
  const roleMap: Record<string, BeeLearntRole> = {
    owner: "ADMIN",
    administrator: "ADMIN",
    superadmin: "ADMIN",
    super_admin: "ADMIN",
    teacher: "TUTOR",
    instructor: "TUTOR",
    educator: "TUTOR",
    facilitator: "TUTOR",
    guardian: "PARENT",
    caregiver: "PARENT",
    learner: "STUDENT",
    member: "STUDENT",
    user: "STUDENT",
  };

  return roleMap[role.toLowerCase().trim()] || DEFAULT_ROLE;
}

// ─── User Sync ──────────────────────────────────────────────

/**
 * Sync user from neondb.neon_auth.user → beelearnt.public.users
 * Called during authentication to ensure user exists in our app database.
 */
export async function syncUserFromNeonAuth(
  neonAuthUserId: string,
  organizationId?: string | null,
) {
  const neonDb = ensureAuthDb();

  try {
    // Get user from neondb.neon_auth.user
    const [neonUser] = await neonDb
      .select()
      .from(neonAuthUsers)
      .where(eq(neonAuthUsers.id, neonAuthUserId))
      .limit(1);

    if (!neonUser) {
      throw new Error(`User ${neonAuthUserId} not found in neondb`);
    }

    console.log(`Syncing user from neondb: ${neonUser.email} (${neonUser.id})`);

    // Check if user exists in beelearnt.public.users
    const [existingUser] = await appDb
      .select()
      .from(users)
      .where(eq(users.id, neonUser.id))
      .limit(1);

    // Determine role (member role can override base role)
    const baseRole = normalizeRole(neonUser.role);
    const userRole = await getUserEffectiveRole(
      neonUser.id,
      organizationId ?? undefined,
      baseRole,
    );

    // If neondb.user has no role set, persist the computed role
    if (!neonUser.role) {
      await neonDb
        .update(neonAuthUsers)
        .set({ role: userRole, updatedAt: new Date() })
        .where(eq(neonAuthUsers.id, neonUser.id));
    }

    // Get role ID from beelearnt.roles
    const [roleRecord] = await appDb
      .select()
      .from(roles)
      .where(eq(roles.name, userRole))
      .limit(1);

    if (!roleRecord) {
      throw new Error(`Role ${userRole} not found in beelearnt database`);
    }

    if (existingUser) {
      // Update existing user in beelearnt.users
      const [updated] = await appDb
        .update(users)
        .set({
          name: neonUser.name,
          email: neonUser.email,
          image: neonUser.image,
          roleId: roleRecord.id,
          updatedAt: new Date(),
        })
        .where(eq(users.id, neonUser.id))
        .returning();

      console.log(`Updated user in beelearnt.users: ${updated.email} (Role: ${userRole})`);

      return {
        user: updated,
        id: updated.id,
        email: updated.email,
        name: updated.name,
        role: userRole,
        isNewUser: false,
      };
    } else {
      // Create new user in beelearnt.users
      const [newUser] = await appDb
        .insert(users)
        .values({
          id: neonUser.id,
          name: neonUser.name ?? "User",
          email: neonUser.email,
          image: neonUser.image,
          roleId: roleRecord.id,
          createdAt: neonUser.createdAt ?? new Date(),
          updatedAt: new Date(),
        })
        .returning();

      console.log(`Created user in beelearnt.users: ${newUser.email} (Role: ${userRole})`);

      return {
        user: newUser,
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        role: userRole,
        isNewUser: true,
      };
    }
  } catch (error) {
    if (isNeonAuthMissingError(error)) {
      return null;
    }
    console.error("[syncUserFromNeonAuth] Error:", error);
    throw error;
  }
}

/**
 * Alias for syncUserFromNeonAuth (used by auth controller token exchange).
 */
export const syncNeonAuthUserToApp = syncUserFromNeonAuth;

// ─── User Queries ───────────────────────────────────────────

/**
 * Get user with role from neondb.neon_auth.user
 */
export async function getNeonAuthUser(
  userId: string,
  organizationId?: string | null,
) {
  const neonDb = ensureAuthDb();

  try {
    const [user] = await neonDb
      .select({
        id: neonAuthUsers.id,
        name: neonAuthUsers.name,
        email: neonAuthUsers.email,
        emailVerified: neonAuthUsers.emailVerified,
        image: neonAuthUsers.image,
        role: neonAuthUsers.role,
        banned: neonAuthUsers.banned,
        banReason: neonAuthUsers.banReason,
        banExpires: neonAuthUsers.banExpires,
        createdAt: neonAuthUsers.createdAt,
        updatedAt: neonAuthUsers.updatedAt,
      })
      .from(neonAuthUsers)
      .where(eq(neonAuthUsers.id, userId))
      .limit(1);

    if (!user) {
      return null;
    }

    // Determine role with membership override
    const baseRole = normalizeRole(user.role);
    const userRole = await getUserEffectiveRole(
      userId,
      organizationId ?? undefined,
      baseRole,
    );

    // If no role set, persist the computed role
    if (!user.role) {
      await neonDb
        .update(neonAuthUsers)
        .set({ role: userRole, updatedAt: new Date() })
        .where(eq(neonAuthUsers.id, userId));
    }

    // Check if banned
    if (user.banned) {
      const now = new Date();
      if (!user.banExpires || user.banExpires > now) {
        throw new Error(`User is banned: ${user.banReason || "No reason provided"}`);
      }
    }

    return {
      ...user,
      role: userRole,
    };
  } catch (error) {
    if (isNeonAuthMissingError(error)) {
      return null;
    }
    console.error("[getNeonAuthUser] Error:", error);
    throw error;
  }
}

/**
 * Check if user exists in Neon Auth by email
 */
export async function getNeonAuthUserByEmail(email: string) {
  if (!isNeonAuthAvailable() || !authDb) {
    return null;
  }

  try {
    const [user] = await authDb
      .select({
        id: neonAuthUsers.id,
        email: neonAuthUsers.email,
        emailVerified: neonAuthUsers.emailVerified,
        banned: neonAuthUsers.banned,
        banReason: neonAuthUsers.banReason,
        banExpires: neonAuthUsers.banExpires,
      })
      .from(neonAuthUsers)
      .where(eq(neonAuthUsers.email, email))
      .limit(1);

    return user || null;
  } catch (error) {
    if (!isNeonAuthMissingError(error)) {
      console.error("[getNeonAuthUserByEmail] Error:", error);
    }
    return null;
  }
}

// ─── Session Verification ───────────────────────────────────

/**
 * Verify session token from neondb.neon_auth.session
 */
export async function verifyNeonAuthSession(token: string) {
  const neonDb = ensureAuthDb();

  try {
    const [session] = await neonDb
      .select({
        session: neonAuthSessions,
        user: neonAuthUsers,
      })
      .from(neonAuthSessions)
      .innerJoin(neonAuthUsers, eq(neonAuthSessions.userId, neonAuthUsers.id))
      .where(eq(neonAuthSessions.token, token))
      .limit(1);

    if (!session) {
      return null;
    }

    // Check if session expired
    const now = new Date();
    if (session.session.expiresAt < now) {
      return null;
    }

    // Check if user is banned
    if (session.user.banned) {
      if (!session.user.banExpires || session.user.banExpires > now) {
        throw new Error(`User is banned: ${session.user.banReason || "No reason provided"}`);
      }
    }

    const baseRole = normalizeRole(session.user.role);
    const organizationId = session.session.activeOrganizationId ?? undefined;
    const userRole = await getUserEffectiveRole(
      session.user.id,
      organizationId,
      baseRole,
    );

    if (!session.user.role) {
      await neonDb
        .update(neonAuthUsers)
        .set({ role: userRole, updatedAt: new Date() })
        .where(eq(neonAuthUsers.id, session.user.id));
    }

    return {
      session: session.session,
      user: {
        ...session.user,
        role: userRole,
      },
    };
  } catch (error) {
    // 42P01 = relation "session" does not exist — neondb tables not created yet
    if (isNeonAuthMissingError(error)) {
      return null;
    }
    console.error("[verifyNeonAuthSession] Error:", error);
    throw error;
  }
}

// ─── Credential Authentication ──────────────────────────────

/**
 * Authenticate user via Neon Auth credential account.
 * Checks neondb.neon_auth.account table for a "credential" provider entry
 * and compares the password hash stored there.
 * On success, syncs the user to beelearnt and returns user data.
 */
export async function authenticateViaNeonAuth(email: string, password: string) {
  if (!isNeonAuthAvailable() || !authDb) return null;

  try {
    // Find user by email in neondb
    const [neonUser] = await authDb
      .select({
        id: neonAuthUsers.id,
        email: neonAuthUsers.email,
        name: neonAuthUsers.name,
        role: neonAuthUsers.role,
      })
      .from(neonAuthUsers)
      .where(eq(neonAuthUsers.email, email))
      .limit(1);

    if (!neonUser) return null;

    // Find credential-style account for this user (supports legacy providerId="email")
    const [account] = await authDb
      .select({ password: neonAuthAccounts.password })
      .from(neonAuthAccounts)
      .where(
        and(
          eq(neonAuthAccounts.userId, neonUser.id),
          sql`${neonAuthAccounts.providerId} IN ('credential', 'email')`,
        ),
      )
      .limit(1);

    if (!account?.password) return null;

    // Compare password against the hash stored in neondb.account
    const valid = await bcrypt.compare(password, account.password);
    if (!valid) return null;

    console.log(`✓ Neon Auth credential login successful: ${email}`);

    // Sync user from neondb to beelearnt
    const syncResult = await syncUserFromNeonAuth(neonUser.id);
    return syncResult;
  } catch (error: any) {
    if (!isNeonAuthMissingError(error)) {
      console.error("[authenticateViaNeonAuth] Error:", error.message);
    }
    return null;
  }
}

// ─── Role Management ────────────────────────────────────────

/**
 * Update user role in neondb (admin only)
 */
export async function updateNeonAuthUserRole(userId: string, newRole: BeeLearntRole) {
  const neonDb = ensureAuthDb();

  try {
    if (!VALID_ROLES.includes(newRole)) {
      throw new Error(`Invalid role: ${newRole}. Must be STUDENT, PARENT, TUTOR, or ADMIN`);
    }

    const [updated] = await neonDb
      .update(neonAuthUsers)
      .set({
        role: newRole,
        updatedAt: new Date(),
      })
      .where(eq(neonAuthUsers.id, userId))
      .returning();

    if (!updated) {
      throw new Error(`User ${userId} not found in neondb`);
    }

    // Sync to beelearnt.users
    await syncUserFromNeonAuth(userId);

    return updated;
  } catch (error) {
    console.error("[updateNeonAuthUserRole] Error:", error);
    throw error;
  }
}

/**
 * Ban/unban user in neondb
 */
export async function updateNeonAuthUserBanStatus(
  userId: string,
  banned: boolean,
  reason?: string,
  expiresAt?: Date,
) {
  const neonDb = ensureAuthDb();

  try {
    const [updated] = await neonDb
      .update(neonAuthUsers)
      .set({
        banned,
        banReason: banned ? reason || "No reason provided" : null,
        banExpires: banned ? expiresAt || null : null,
        updatedAt: new Date(),
      })
      .where(eq(neonAuthUsers.id, userId))
      .returning();

    if (!updated) {
      throw new Error(`User ${userId} not found in neondb`);
    }

    return updated;
  } catch (error) {
    console.error("[updateNeonAuthUserBanStatus] Error:", error);
    throw error;
  }
}

/**
 * Set initial role for a new user in neondb
 */
export async function setInitialUserRole(userId: string, role: BeeLearntRole) {
  const neonDb = ensureAuthDb();

  try {
    if (!VALID_ROLES.includes(role)) {
      throw new Error(`Invalid role: ${role}. Must be STUDENT, PARENT, TUTOR, or ADMIN`);
    }

    const [updated] = await neonDb
      .update(neonAuthUsers)
      .set({
        role,
        updatedAt: new Date(),
      })
      .where(eq(neonAuthUsers.id, userId))
      .returning();

    if (!updated) {
      throw new Error(`User ${userId} not found in neondb`);
    }

    // Sync to beelearnt.users
    await syncUserFromNeonAuth(userId);

    return updated;
  } catch (error) {
    console.error("[setInitialUserRole] Error:", error);
    throw error;
  }
}

// ─── Role Queries ───────────────────────────────────────────

/**
 * Check if user has a specific role
 */
export async function userHasRole(userId: string, role: BeeLearntRole): Promise<boolean> {
  try {
    const user = await getNeonAuthUser(userId);
    return user?.role === role;
  } catch {
    return false;
  }
}

/**
 * Check if user has any of the specified roles
 */
export async function userHasAnyRole(userId: string, roleList: BeeLearntRole[]): Promise<boolean> {
  try {
    const user = await getNeonAuthUser(userId);
    return user ? roleList.includes(user.role) : false;
  } catch {
    return false;
  }
}

/**
 * Get all users with a specific role (from neondb)
 */
export async function getUsersByRole(role: BeeLearntRole) {
  const neonDb = ensureAuthDb();

  try {
    return await neonDb
      .select({
        id: neonAuthUsers.id,
        name: neonAuthUsers.name,
        email: neonAuthUsers.email,
        role: neonAuthUsers.role,
        createdAt: neonAuthUsers.createdAt,
      })
      .from(neonAuthUsers)
      .where(eq(neonAuthUsers.role, role));
  } catch (error) {
    console.error("[getUsersByRole] Error:", error);
    throw error;
  }
}
