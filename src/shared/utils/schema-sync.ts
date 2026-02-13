/**
 * Schema Sync Utility
 *
 * Two separate databases:
 *   neondb  (Neon Auth, auto-created) → "user", "account" tables (public schema)
 *   beelearnt (application)           → "users", "roles" tables (public schema)
 *
 * There is NO "neon_auth" schema. Cross-database JOINs are impossible,
 * so each function queries one database at a time.
 *
 * Key Mappings:
 * - neondb.user.id    ↔ beelearnt.users.id (both uuid)
 * - neondb.user.email ↔ beelearnt.users.email
 * - neondb.user.name  ↔ beelearnt.users.name
 * - neondb.user.image ↔ beelearnt.users.image
 * - neondb.user.role  ↔ beelearnt.roles.name (via users.role_id)
 * - neondb.account.password → password for Neon Auth
 * - beelearnt.users.password_hash → password for local auth
 */

import { eq, sql } from "drizzle-orm";
import { db as appDb } from "../../core/database/index.js";
import { db as authDb } from "../../core/database/neon-auth-db.js";
import {
  neonAuthUsers,
  neonAuthAccounts,
} from "../../core/database/neon-auth-schema.js";
import { users, roles } from "../../core/database/schema/index.js";
import type { BeeLearntRole } from "../types/auth.js";

interface SyncUserInput {
  id: string;
  email: string;
  name: string;
  role: BeeLearntRole;
  image?: string | null;
}

interface SyncPasswordInput {
  userId: string;
  email: string;
  passwordHash: string;
}

const VALID_ROLES = ["STUDENT", "PARENT", "ADMIN", "TUTOR"];

/**
 * Sync user data from beelearnt.users → neondb.user
 */
export async function syncToNeonAuthUser(input: SyncUserInput): Promise<void> {
  if (!authDb) {
    throw Object.assign(new Error("Neon Auth database not configured"), { code: "3F000" });
  }

  const normalizedRole = input.role.toUpperCase();
  if (!VALID_ROLES.includes(normalizedRole)) {
    throw new Error(`Invalid role "${normalizedRole}". Must be STUDENT, PARENT, ADMIN, or TUTOR.`);
  }

  try {
    // Check if user already exists in neondb
    const [existing] = await authDb
      .select({ id: neonAuthUsers.id })
      .from(neonAuthUsers)
      .where(eq(neonAuthUsers.id, input.id))
      .limit(1);

    if (existing) {
      await authDb
        .update(neonAuthUsers)
        .set({
          email: input.email,
          name: input.name,
          role: normalizedRole,
          image: input.image ?? null,
          updatedAt: new Date(),
        })
        .where(eq(neonAuthUsers.id, input.id));
    } else {
      await authDb.insert(neonAuthUsers).values({
        id: input.id,
        email: input.email,
        name: input.name,
        role: normalizedRole,
        image: input.image ?? null,
        emailVerified: false,
        banned: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    }
  } catch (error) {
    console.error("[syncToNeonAuthUser] Failed:", error);
    throw error;
  }
}

/**
 * Sync user data from neondb.user → beelearnt.users
 */
export async function syncFromNeonAuthUser(input: {
  id: string;
  email: string;
  name: string;
  role: BeeLearntRole;
  image?: string | null;
}): Promise<void> {
  const normalizedRole = input.role.toUpperCase();
  if (!VALID_ROLES.includes(normalizedRole)) {
    throw new Error(`Invalid role "${normalizedRole}". Must be STUDENT, PARENT, ADMIN, or TUTOR.`);
  }

  try {
    // Get role ID from beelearnt.roles
    const roleResult = await appDb.execute<{ id: number }>(sql`
      SELECT id FROM roles WHERE name = ${normalizedRole}
    `);

    if (!roleResult.rows[0]) {
      throw new Error(`Role ${normalizedRole} not found in beelearnt.roles`);
    }

    const roleId = roleResult.rows[0].id;

    await appDb.execute(sql`
      INSERT INTO users (
        id, email, name, image, role_id, created_at, updated_at
      )
      VALUES (
        ${input.id}::uuid,
        ${input.email},
        ${input.name},
        ${input.image ?? null},
        ${roleId},
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
  } catch (error) {
    console.error("[syncFromNeonAuthUser] Failed:", error);
    throw error;
  }
}

/**
 * Sync password to neondb.account
 */
export async function syncPasswordToNeonAuth(input: SyncPasswordInput): Promise<void> {
  if (!authDb) {
    throw Object.assign(new Error("Neon Auth database not configured"), { code: "3F000" });
  }

  try {
    // Check if credential/email account already exists
    const [existing] = await authDb
      .select({ id: neonAuthAccounts.id })
      .from(neonAuthAccounts)
      .where(
        sql`${neonAuthAccounts.userId} = ${input.userId} AND ${neonAuthAccounts.providerId} IN ('credential', 'email')`,
      )
      .limit(1);

    if (existing) {
      await authDb
        .update(neonAuthAccounts)
        .set({
          providerId: "credential",
          accountId: input.email,
          password: input.passwordHash,
          updatedAt: new Date(),
        })
        .where(eq(neonAuthAccounts.id, existing.id));
    } else {
      await authDb.insert(neonAuthAccounts).values({
        id: sql`gen_random_uuid()`.mapWith(String) as any,
        userId: input.userId,
        providerId: "credential",
        accountId: input.email,
        password: input.passwordHash,
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    }
  } catch (error) {
    console.error("[syncPasswordToNeonAuth] Failed:", error);
    throw error;
  }
}

/**
 * Get user data from neondb.user
 */
export async function getNeonAuthUser(userId: string) {
  if (!authDb) return null;

  try {
    const [user] = await authDb
      .select({
        id: neonAuthUsers.id,
        email: neonAuthUsers.email,
        name: neonAuthUsers.name,
        role: neonAuthUsers.role,
        image: neonAuthUsers.image,
        emailVerified: neonAuthUsers.emailVerified,
        banned: neonAuthUsers.banned,
      })
      .from(neonAuthUsers)
      .where(eq(neonAuthUsers.id, userId))
      .limit(1);

    return user || null;
  } catch (error) {
    console.error("[getNeonAuthUser] Failed:", error);
    return null;
  }
}

/**
 * Get password from neondb.account
 */
export async function getNeonAuthPassword(userId: string): Promise<string | null> {
  if (!authDb) return null;

  try {
    const [account] = await authDb
      .select({ password: neonAuthAccounts.password })
      .from(neonAuthAccounts)
      .where(
        sql`${neonAuthAccounts.userId} = ${userId} AND ${neonAuthAccounts.providerId} IN ('credential', 'email')`,
      )
      .limit(1);

    return account?.password || null;
  } catch (error) {
    console.error("[getNeonAuthPassword] Failed:", error);
    return null;
  }
}

/**
 * Sync all users from beelearnt.users → neondb.user
 */
export async function syncAllUsersToNeonAuth(): Promise<{ synced: number; failed: number }> {
  if (!authDb) {
    console.warn("Neon Auth database not configured, skipping sync");
    return { synced: 0, failed: 0 };
  }

  console.log("Syncing all users from beelearnt.users to neondb.user...");

  let synced = 0;
  let failed = 0;

  try {
    const result = await appDb.execute<{
      id: string;
      email: string;
      name: string;
      image: string | null;
      role: string;
      password_hash: string | null;
    }>(sql`
      SELECT
        u.id::text,
        u.email,
        u.name,
        u.image,
        r.name as role,
        u.password_hash
      FROM users u
      JOIN roles r ON u.role_id = r.id
      ORDER BY u.created_at ASC
    `);

    console.log(`Found ${result.rows.length} users to sync`);

    for (const user of result.rows) {
      try {
        const normalizedRole = user.role.toUpperCase() as BeeLearntRole;

        await syncToNeonAuthUser({
          id: user.id,
          email: user.email,
          name: user.name,
          role: normalizedRole,
          image: user.image,
        });

        if (user.password_hash) {
          try {
            await syncPasswordToNeonAuth({
              userId: user.id,
              email: user.email,
              passwordHash: user.password_hash,
            });
          } catch {
            console.warn(`  Password sync skipped for ${user.email}`);
          }
        }

        synced++;
      } catch (error) {
        failed++;
        console.error(`Failed to sync ${user.email}:`, error);
      }
    }

    console.log(`Sync complete: ${synced} synced, ${failed} failed`);
    return { synced, failed };
  } catch (error) {
    console.error("Fatal error during sync:", error);
    throw error;
  }
}

/**
 * Verify schema consistency between neondb.user and beelearnt.users
 * Since cross-database JOINs are impossible, queries each DB separately
 */
export async function verifySchemaConsistency(): Promise<{
  consistent: boolean;
  mismatches: Array<{ userId: string; issue: string }>;
}> {
  console.log("Verifying schema consistency...");

  const mismatches: Array<{ userId: string; issue: string }> = [];

  if (!authDb) {
    console.warn("Neon Auth database not configured, skipping consistency check");
    return { consistent: true, mismatches: [] };
  }

  try {
    // Get all users from beelearnt
    const appUsers = await appDb.execute<{
      id: string;
      email: string;
      role: string;
    }>(sql`
      SELECT u.id::text, u.email, r.name as role
      FROM users u
      JOIN roles r ON u.role_id = r.id
    `);

    // Get all users from neondb
    const neonUsers = await authDb
      .select({
        id: neonAuthUsers.id,
        email: neonAuthUsers.email,
        role: neonAuthUsers.role,
      })
      .from(neonAuthUsers);

    // Build neon user map
    const neonUserMap = new Map(neonUsers.map((u) => [u.id, u]));

    for (const appUser of appUsers.rows) {
      const neonUser = neonUserMap.get(appUser.id);

      if (!neonUser) {
        mismatches.push({
          userId: appUser.id,
          issue: `User ${appUser.email} exists in beelearnt.users but not in neondb.user`,
        });
        continue;
      }

      if (appUser.role.toUpperCase() !== (neonUser.role ?? "").toUpperCase()) {
        mismatches.push({
          userId: appUser.id,
          issue: `Role mismatch for ${appUser.email}: beelearnt=${appUser.role}, neondb=${neonUser.role}`,
        });
      }

      if (appUser.email !== neonUser.email) {
        mismatches.push({
          userId: appUser.id,
          issue: `Email mismatch: beelearnt=${appUser.email}, neondb=${neonUser.email}`,
        });
      }
    }

    const consistent = mismatches.length === 0;

    if (consistent) {
      console.log("Schemas are consistent!");
    } else {
      console.log(`Found ${mismatches.length} inconsistencies`);
    }

    return { consistent, mismatches };
  } catch (error) {
    console.error("Error verifying consistency:", error);
    throw error;
  }
}
