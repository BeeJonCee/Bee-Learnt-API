import { randomUUID } from "crypto";
import { eq, sql } from "drizzle-orm";
import { db as appDb } from "../core/database/index.js";
import { db as authDb } from "../core/database/neon-auth-db.js";
import { neonAuthUsers, neonAuthMembers } from "../core/database/neon-auth-schema.js";
import { roles, users } from "../core/database/schema/index.js";
import type { BeeLearntRole } from "../shared/types/auth.js";
import { syncToNeonAuthUser as syncNeonUser } from "../shared/utils/schema-sync.js";

const roleIdCache = new Map<BeeLearntRole, number>();

async function ensureRole(role: BeeLearntRole) {
  const cached = roleIdCache.get(role);
  if (cached) return cached;

  const [existing] = await appDb.select().from(roles).where(eq(roles.name, role));
  if (existing) {
    roleIdCache.set(role, existing.id);
    return existing.id;
  }

  const [created] = await appDb
    .insert(roles)
    .values({
      name: role,
      description: `${role} role`,
    })
    .returning();

  roleIdCache.set(role, created.id);
  return created.id;
}

async function ensureNeonUser(input: {
  id: string;
  email: string;
  name?: string | null;
  role?: BeeLearntRole | null;
}) {
  if (!authDb) return;

  const [existing] = await authDb
    .select({ id: neonAuthUsers.id })
    .from(neonAuthUsers)
    .where(eq(neonAuthUsers.id, input.id));
  if (existing) return;

  await authDb.insert(neonAuthUsers).values({
    id: input.id,
    email: input.email,
    name: input.name ?? "",
    role: input.role ?? null,
    emailVerified: false,
    banned: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  });
}

const normalizeBeeRole = (value?: string | null): BeeLearntRole | null => {
  if (!value) return null;
  const upper = value.toUpperCase();
  if (upper === "ADMIN" || upper === "PARENT" || upper === "STUDENT" || upper === "TUTOR") {
    return upper as BeeLearntRole;
  }
  return null;
};

const mapMemberRole = (value?: string | null): BeeLearntRole | null => {
  const direct = normalizeBeeRole(value);
  if (direct) return direct;
  const normalized = value?.trim().toLowerCase();
  if (!normalized) return null;
  if (["owner", "admin", "administrator", "superadmin", "staff"].includes(normalized)) {
    return "ADMIN";
  }
  if (["tutor", "teacher", "instructor", "educator", "facilitator"].includes(normalized)) {
    return "TUTOR";
  }
  if (["parent", "guardian"].includes(normalized)) {
    return "PARENT";
  }
  if (["student", "member", "learner", "user"].includes(normalized)) {
    return "STUDENT";
  }
  return null;
};

const pickHighestRole = (rolesToPick: BeeLearntRole[]) => {
  if (rolesToPick.includes("ADMIN")) return "ADMIN";
  if (rolesToPick.includes("TUTOR")) return "TUTOR";
  if (rolesToPick.includes("PARENT")) return "PARENT";
  return "STUDENT";
};

async function resolveRoleFromMembership(input: {
  userId: string;
  organizationId?: string | null;
}): Promise<BeeLearntRole | null> {
  if (!authDb) return null;

  try {
    // Query neondb.member via authDb
    const condition = input.organizationId
      ? sql`${neonAuthMembers.userId} = ${input.userId} AND ${neonAuthMembers.organizationId} = ${input.organizationId}`
      : sql`${neonAuthMembers.userId} = ${input.userId}`;

    const result = await authDb
      .select({ role: neonAuthMembers.role })
      .from(neonAuthMembers)
      .where(condition)
      .limit(5);

    if (result.length === 0) {
      return null;
    }

    const memberRoles = result.map((row) => mapMemberRole(row.role));
    const validRoles = memberRoles.filter((role): role is BeeLearntRole => Boolean(role));

    if (validRoles.length === 0) return null;
    return pickHighestRole(validRoles);
  } catch (error) {
    console.error("Error resolving role from membership:", error);
    return null;
  }
}

export async function getOrCreateUserByEmail(input: {
  id?: string | null;
  email: string;
  name?: string | null;
  role?: BeeLearntRole | null;
  organizationId?: string | null;
}) {
  const membershipRole = input.id
    ? await resolveRoleFromMembership({ userId: input.id, organizationId: input.organizationId })
    : null;
  const effectiveRole = membershipRole ?? input.role ?? "STUDENT";

  if (input.id) {
    await ensureNeonUser({
      id: input.id,
      email: input.email,
      name: input.name,
      role: effectiveRole,
    });
    const [existingById] = await appDb
      .select({
        id: users.id,
        name: users.name,
        email: users.email,
        role: roles.name,
      })
      .from(users)
      .innerJoin(roles, eq(users.roleId, roles.id))
      .where(eq(users.id, input.id));

    if (existingById) {
      const updates: { roleId?: number; name?: string; email?: string } = {};
      if (existingById.role !== effectiveRole) {
        updates.roleId = await ensureRole(effectiveRole);
      }
      if (input.name && input.name.trim() && input.name !== existingById.name) {
        updates.name = input.name.trim();
      }
      if (input.email && input.email !== existingById.email) {
        updates.email = input.email;
      }

      if (Object.keys(updates).length > 0) {
        await appDb.update(users).set({ ...updates, updatedAt: new Date() }).where(eq(users.id, existingById.id));

        // Sync to neondb.user (optional)
        try {
          await syncNeonUser({
            id: existingById.id,
            email: updates.email ?? existingById.email,
            name: updates.name ?? existingById.name,
            role: effectiveRole,
          });
        } catch (error: any) {
          if (error?.code !== "42P01" && error?.code !== "3F000") {
            console.warn("Could not sync to neondb:", error.message);
          }
        }

        return {
          ...existingById,
          ...updates,
          role: effectiveRole,
          name: updates.name ?? existingById.name,
          email: updates.email ?? existingById.email,
        };
      }

      return existingById;
    }
  }

  const [existingByEmail] = await appDb
    .select({
      id: users.id,
      name: users.name,
      email: users.email,
      role: roles.name,
    })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id))
    .where(eq(users.email, input.email));

  if (existingByEmail) {
    if (existingByEmail.role !== effectiveRole) {
      const roleId = await ensureRole(effectiveRole);
      await appDb.update(users).set({ roleId }).where(eq(users.id, existingByEmail.id));
      return {
        ...existingByEmail,
        role: effectiveRole,
      };
    }
    return existingByEmail;
  }

  const roleId = await ensureRole(effectiveRole);
  const displayName = input.name?.trim() || input.email.split("@")[0] || "Student";
  const userId = input.id ?? randomUUID();

  const [created] = await appDb
    .insert(users)
    .values({
      id: userId,
      name: displayName,
      email: input.email,
      image: null,
      roleId,
    })
    .returning();

  // Sync to neondb.user (optional)
  try {
    await syncNeonUser({
      id: created.id,
      email: created.email,
      name: created.name,
      role: effectiveRole,
    });
  } catch (error: any) {
    if (error?.code !== "42P01" && error?.code !== "3F000") {
      console.warn("Could not sync to neondb:", error.message);
    }
  }

  return {
    id: created.id,
    name: created.name,
    email: created.email,
    role: effectiveRole,
  };
}
