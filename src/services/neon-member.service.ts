import { eq, and, sql } from "drizzle-orm";
import { db as authDb } from "../core/database/neon-auth-db.js";
import {
  neonAuthMembers,
  neonAuthUsers,
  neonAuthOrganizations,
} from "../core/database/neon-auth-schema.js";
import type { BeeLearntRole } from "../shared/types/auth.js";

/**
 * Service to manage neondb.member table and organization roles
 *
 * Two separate databases:
 *   neondb  → member, user, organization tables (public schema)
 *   beelearnt → application tables
 *
 * There is NO "neon_auth" schema — everything is in neondb.public.
 */

export interface NeonMember {
  id: string;
  userId: string;
  organizationId: string;
  role: string;
  createdAt: Date;
}

/**
 * Map neondb.member roles to BeeLearnt roles
 */
export function mapMemberRoleToBeeRole(memberRole: string): BeeLearntRole | null {
  const normalized = memberRole?.trim().toLowerCase();
  if (!normalized) return null;

  if (["owner", "admin", "administrator", "superadmin"].includes(normalized)) {
    return "ADMIN";
  }

  if (["tutor", "teacher", "instructor", "educator", "facilitator"].includes(normalized)) {
    return "TUTOR";
  }

  if (["parent", "guardian", "moderator"].includes(normalized)) {
    return "PARENT";
  }

  if (["member", "student", "learner", "user"].includes(normalized)) {
    return "STUDENT";
  }

  return null;
}

/**
 * Get user's member roles from neondb.member
 */
export async function getUserMemberRoles(
  userId: string,
  organizationId?: string
): Promise<BeeLearntRole[]> {
  if (!authDb) return [];

  try {
    const condition = organizationId
      ? and(
          eq(neonAuthMembers.userId, userId),
          eq(neonAuthMembers.organizationId, organizationId),
        )
      : eq(neonAuthMembers.userId, userId);

    const result = await authDb
      .select({ role: neonAuthMembers.role })
      .from(neonAuthMembers)
      .where(condition);

    const beeRoles: BeeLearntRole[] = [];
    for (const row of result) {
      const mapped = mapMemberRoleToBeeRole(row.role);
      if (mapped) {
        beeRoles.push(mapped);
      }
    }

    return beeRoles;
  } catch (error) {
    console.error("Error getting user member roles:", error);
    return [];
  }
}

/**
 * Get the highest priority role from a list
 * Priority: ADMIN > TUTOR > PARENT > STUDENT
 */
export function getHighestRole(roleList: BeeLearntRole[]): BeeLearntRole {
  if (roleList.includes("ADMIN")) return "ADMIN";
  if (roleList.includes("TUTOR")) return "TUTOR";
  if (roleList.includes("PARENT")) return "PARENT";
  return "STUDENT";
}

/**
 * Get user's effective role (highest from member roles or default)
 */
export async function getUserEffectiveRole(
  userId: string,
  organizationId?: string,
  defaultRole: BeeLearntRole = "STUDENT"
): Promise<BeeLearntRole> {
  const memberRoles = await getUserMemberRoles(userId, organizationId);

  if (memberRoles.length === 0) {
    return defaultRole;
  }

  // Never downgrade: membership roles can elevate privileges
  return getHighestRole([defaultRole, ...memberRoles]);
}

/**
 * Create a member in neondb.member
 */
export async function createMember(input: {
  userId: string;
  organizationId: string;
  role: string;
}): Promise<void> {
  if (!authDb) throw new Error("Neon Auth database not configured");

  try {
    await authDb
      .insert(neonAuthMembers)
      .values({
        id: sql`gen_random_uuid()`.mapWith(String) as any,
        userId: input.userId,
        organizationId: input.organizationId,
        role: input.role,
        createdAt: new Date(),
      })
      .onConflictDoNothing();
  } catch (error) {
    console.error("Error creating member:", error);
    throw error;
  }
}

/**
 * Update member role in neondb.member
 */
export async function updateMemberRole(input: {
  userId: string;
  organizationId: string;
  role: string;
}): Promise<void> {
  if (!authDb) throw new Error("Neon Auth database not configured");

  try {
    await authDb
      .update(neonAuthMembers)
      .set({ role: input.role })
      .where(
        and(
          eq(neonAuthMembers.userId, input.userId),
          eq(neonAuthMembers.organizationId, input.organizationId),
        ),
      );
  } catch (error) {
    console.error("Error updating member role:", error);
    throw error;
  }
}

/**
 * Remove member from organization
 */
export async function removeMember(userId: string, organizationId: string): Promise<void> {
  if (!authDb) throw new Error("Neon Auth database not configured");

  try {
    await authDb
      .delete(neonAuthMembers)
      .where(
        and(
          eq(neonAuthMembers.userId, userId),
          eq(neonAuthMembers.organizationId, organizationId),
        ),
      );
  } catch (error) {
    console.error("Error removing member:", error);
    throw error;
  }
}

/**
 * Get all members of an organization
 */
export async function getOrganizationMembers(organizationId: string): Promise<Array<NeonMember & { email?: string; name?: string }>> {
  if (!authDb) return [];

  try {
    const result = await authDb
      .select({
        id: neonAuthMembers.id,
        userId: neonAuthMembers.userId,
        organizationId: neonAuthMembers.organizationId,
        role: neonAuthMembers.role,
        createdAt: neonAuthMembers.createdAt,
        email: neonAuthUsers.email,
        name: neonAuthUsers.name,
      })
      .from(neonAuthMembers)
      .leftJoin(neonAuthUsers, eq(neonAuthMembers.userId, neonAuthUsers.id))
      .where(eq(neonAuthMembers.organizationId, organizationId))
      .orderBy(neonAuthMembers.createdAt);

    return result.map((row) => ({
      id: row.id,
      userId: row.userId,
      organizationId: row.organizationId,
      role: row.role,
      createdAt: row.createdAt,
      email: row.email ?? undefined,
      name: row.name ?? undefined,
    }));
  } catch (error) {
    console.error("Error getting organization members:", error);
    return [];
  }
}

/**
 * Get all organizations a user belongs to
 */
export async function getUserOrganizations(userId: string): Promise<Array<{
  id: string;
  name: string;
  slug: string;
  role: string;
  beeRole: BeeLearntRole | null;
}>> {
  if (!authDb) return [];

  try {
    const result = await authDb
      .select({
        id: neonAuthOrganizations.id,
        name: neonAuthOrganizations.name,
        slug: neonAuthOrganizations.slug,
        role: neonAuthMembers.role,
      })
      .from(neonAuthMembers)
      .innerJoin(neonAuthOrganizations, eq(neonAuthMembers.organizationId, neonAuthOrganizations.id))
      .where(eq(neonAuthMembers.userId, userId))
      .orderBy(neonAuthMembers.createdAt);

    return result.map((row) => ({
      id: row.id,
      name: row.name,
      slug: row.slug,
      role: row.role,
      beeRole: mapMemberRoleToBeeRole(row.role),
    }));
  } catch (error) {
    console.error("Error getting user organizations:", error);
    return [];
  }
}

/**
 * Check if user has a specific member role in any organization
 */
export async function hasOrgRole(userId: string, targetRole: string): Promise<boolean> {
  if (!authDb) return false;

  try {
    const result = await authDb
      .select({ role: neonAuthMembers.role })
      .from(neonAuthMembers)
      .where(eq(neonAuthMembers.userId, userId))
      .limit(10);

    return result.some(
      (row) => row.role.toLowerCase() === targetRole.toLowerCase(),
    );
  } catch (error) {
    console.error("Error checking org role:", error);
    return false;
  }
}
