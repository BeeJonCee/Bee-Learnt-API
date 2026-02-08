/**
 * Neon Auth Sync Utility
 * 
 * Syncs data between two separate databases:
 * - neondb (Neon Auth) - auto-created by Neon
 * - beelearnt (Application) - your app database
 * 
 * Never try to use neon_auth schema - it doesn't exist!
 * All auth tables are in the public schema of the neondb database.
 */

import bcrypt from "bcryptjs";
import type { BeeLearntRole } from "../shared/types/auth.js";
import { env } from "../config/env.js";
import { db as appDb } from "../core/database/index.js";
import { db as authDb } from "../core/database/neon-auth-db.js";
import { neonAuthUsers, neonAuthAccounts } from "../core/database/neon-auth-schema.js";
import { roles, users } from "../core/database/schema/index.js";
import { and, eq, sql } from "drizzle-orm";

const VALID_ROLES: BeeLearntRole[] = ["STUDENT", "PARENT", "TUTOR", "ADMIN"];
const DEFAULT_ROLE: BeeLearntRole = "STUDENT";

const NEON_AUTH_MISSING_CODES = new Set(["42P01", "3F000"]);

function shouldIgnoreNeonAuthError(error: unknown): boolean {
  const code = (error as { code?: string } | null)?.code;
  return !!code && NEON_AUTH_MISSING_CODES.has(code);
}

/**
 * Check if Neon Auth database is configured and available
 */
export function isNeonAuthAvailable(): boolean {
  return !!env.neonAuthDatabaseUrl;
}

/**
 * Sync user from Neon Auth (neondb) to BeeLearnt (beelearnt)
 * Called during OAuth/token exchange
 */
export async function syncNeonAuthUserToApp(neonUserId: string) {
  // If Neon Auth isn't configured, skip sync
  if (!isNeonAuthAvailable()) {
    console.warn("Neon Auth not configured - skipping sync");
    return null;
  }

  if (!authDb) {
    console.warn("Neon Auth database not connected - skipping sync");
    return null;
  }

  try {
    // Get user from neondb.public.user
    const neonUsersResult = await authDb
      .select({
        id: neonAuthUsers.id,
        email: neonAuthUsers.email,
        name: neonAuthUsers.name,
        role: neonAuthUsers.role,
        image: neonAuthUsers.image,
        emailVerified: neonAuthUsers.emailVerified,
        banned: neonAuthUsers.banned,
        banReason: neonAuthUsers.banReason,
        banExpires: neonAuthUsers.banExpires,
        createdAt: neonAuthUsers.createdAt,
      })
      .from(neonAuthUsers)
      .where(eq(neonAuthUsers.id, neonUserId))
      .limit(1);

    const [authUserData] = neonUsersResult;
    if (!authUserData) {
      throw new Error(`User ${neonUserId} not found in neondb`);
    }

    console.log(`✓ Found Neon Auth user: ${authUserData.email}`);

    // Determine role
    const userRole = (authUserData.role?.toUpperCase() || DEFAULT_ROLE) as BeeLearntRole;
    
    // Get role ID from beelearnt database
    const roleRecords = await appDb
      .select({ id: roles.id })
      .from(roles)
      .where(eq(roles.name, userRole))
      .limit(1);

    const [roleRecord] = roleRecords;
    if (!roleRecord) {
      throw new Error(`Role ${userRole} not found in beelearnt.roles`);
    }

    // Upsert user in beelearnt.public.users
    await appDb.execute(sql`
      INSERT INTO users (
        id, email, name, image, role_id, created_at, updated_at
      )
      VALUES (
        ${neonUserId}::uuid,
        ${authUserData.email},
        ${authUserData.name || null},
        ${authUserData.image || null},
        ${roleRecord.id},
        NOW(),
        NOW()
      )
      ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        name = EXCLUDED.name,
        image = EXCLUDED.image,
        role_id = EXCLUDED.role_id,
        updated_at = NOW()
    `);

    console.log(`✓ Synced user to beelearnt: ${authUserData.email}`);

    return {
      id: authUserData.id,
      email: authUserData.email,
      name: authUserData.name || "",
      role: userRole,
      emailVerified: authUserData.emailVerified,
      banned: authUserData.banned,
    };
  } catch (error: any) {
    console.error("[syncNeonAuthUserToApp] Failed:", error.message);
    throw error;
  }
}

/**
 * Get user from Neon Auth database
 */
export async function getNeonAuthUser(userId: string) {
  if (!isNeonAuthAvailable() || !authDb) {
    return null;
  }

  try {
    const usersResult = await authDb
      .select({
        id: neonAuthUsers.id,
        email: neonAuthUsers.email,
        name: neonAuthUsers.name,
        role: neonAuthUsers.role,
        image: neonAuthUsers.image,
        emailVerified: neonAuthUsers.emailVerified,
        banned: neonAuthUsers.banned,
        banReason: neonAuthUsers.banReason,
        banExpires: neonAuthUsers.banExpires,
        createdAt: neonAuthUsers.createdAt,
      })
      .from(neonAuthUsers)
      .where(eq(neonAuthUsers.id, userId))
      .limit(1);

    return usersResult[0] || null;
  } catch (error) {
    if (!shouldIgnoreNeonAuthError(error)) {
      console.error("[getNeonAuthUser] Error:", error);
    }
    return null;
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
    const authUsersResult = await authDb
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

    return authUsersResult[0] || null;
  } catch (error) {
    if (!shouldIgnoreNeonAuthError(error)) {
      console.error("[getNeonAuthUserByEmail] Error:", error);
    }
    return null;
  }
}

/**
 * Authenticate user via Neon Auth credential account.
 * Checks neondb.account table for a "credential" provider entry
 * and compares the password hash stored there.
 * On success, syncs the user to beelearnt and returns user data.
 */
export async function authenticateViaNeonAuth(email: string, password: string) {
  if (!isNeonAuthAvailable() || !authDb) return null;

  try {
    // Find user by email in neondb
    const neonUsersResult = await authDb
      .select({
        id: neonAuthUsers.id,
        email: neonAuthUsers.email,
        name: neonAuthUsers.name,
        role: neonAuthUsers.role,
      })
      .from(neonAuthUsers)
      .where(eq(neonAuthUsers.email, email))
      .limit(1);

    const neonUser = neonUsersResult[0];
    if (!neonUser) return null;

    // Find credential account for this user
    const accountsResult = await authDb
      .select({ password: neonAuthAccounts.password })
      .from(neonAuthAccounts)
      .where(
        and(
          eq(neonAuthAccounts.userId, neonUser.id),
          eq(neonAuthAccounts.providerId, "credential")
        )
      )
      .limit(1);

    const account = accountsResult[0];
    if (!account?.password) return null;

    // Compare password against the hash stored in neondb.account
    const valid = await bcrypt.compare(password, account.password);
    if (!valid) return null;

    console.log(`✓ Neon Auth credential login successful: ${email}`);

    // Sync user from neondb to beelearnt
    const syncResult = await syncNeonAuthUserToApp(neonUser.id);
    return syncResult;
  } catch (error: any) {
    if (!shouldIgnoreNeonAuthError(error)) {
      console.error("[authenticateViaNeonAuth] Error:", error.message);
    }
    return null;
  }
}
