import { eq, sql } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import { users, roles } from "../../core/database/schema/index.js";
import { neonAuthUsers } from "../../core/database/neon-auth-schema.js";

// ── Analytics ────────────────────────────────────────────────────────────────

export async function getAnalytics() {
  const usersByRole = await db
    .select({
      role: roles.name,
      count: sql<number>`count(*)::int`,
    })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id))
    .groupBy(roles.name);

  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

  const [activeUsers] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(users)
    .where(sql`last_login_at >= ${sevenDaysAgo}`);

  const [totalUsers] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(users);

  return {
    totalUsers: totalUsers?.count ?? 0,
    activeUsersLast7Days: activeUsers?.count ?? 0,
    usersByRole: usersByRole.reduce<Record<string, number>>((acc, row) => {
      acc[row.role] = row.count;
      return acc;
    }, {}),
  };
}

// ── Neon Auth Sync ────────────────────────────────────────────────────────────

export async function syncUsersToNeonAuth(): Promise<{
  synced: number;
  skipped: number;
  errors: string[];
}> {
  const allUsers = await db
    .select({
      id: users.id,
      name: users.name,
      email: users.email,
      role: roles.name,
    })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id));

  let synced = 0;
  let skipped = 0;
  const errors: string[] = [];

  for (const user of allUsers) {
    try {
      const [neonUser] = await db
        .select({ id: neonAuthUsers.id, role: neonAuthUsers.role })
        .from(neonAuthUsers)
        .where(sql`${neonAuthUsers.id}::text = ${user.id}`)
        .limit(1);

      if (!neonUser) {
        skipped++;
        continue;
      }

      if (neonUser.role !== user.role) {
        await db
          .update(neonAuthUsers)
          .set({ role: user.role, updatedAt: new Date() })
          .where(sql`${neonAuthUsers.id}::text = ${user.id}`);
        synced++;
      } else {
        skipped++;
      }
    } catch (err) {
      errors.push(`User ${user.id}: ${(err as Error).message}`);
    }
  }

  return { synced, skipped, errors };
}

// ── Schema Consistency Check ──────────────────────────────────────────────────

export async function checkSchemaConsistency(): Promise<{
  consistent: boolean;
  inBeeLearntOnly: string[];
  inNeonAuthOnly: string[];
  roleMismatches: Array<{ userId: string; beeLearntRole: string; neonRole: string | null }>;
}> {
  const beeLearntUsers = await db
    .select({ id: users.id, role: roles.name })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id));

  const neonUsers = await db
    .select({ id: neonAuthUsers.id, role: neonAuthUsers.role })
    .from(neonAuthUsers);

  const neonById = new Map(neonUsers.map((u) => [String(u.id), u.role]));
  const beeLearntIds = new Set(beeLearntUsers.map((u) => u.id));

  const inBeeLearntOnly = beeLearntUsers
    .filter((u) => !neonById.has(u.id))
    .map((u) => u.id);

  const inNeonAuthOnly = neonUsers
    .filter((u) => !beeLearntIds.has(String(u.id)))
    .map((u) => String(u.id));

  const roleMismatches = beeLearntUsers
    .filter((u) => {
      const neonRole = neonById.get(u.id);
      return neonRole !== undefined && neonRole !== u.role;
    })
    .map((u) => ({
      userId: u.id,
      beeLearntRole: u.role,
      neonRole: neonById.get(u.id) ?? null,
    }));

  return {
    consistent: inBeeLearntOnly.length === 0 && inNeonAuthOnly.length === 0 && roleMismatches.length === 0,
    inBeeLearntOnly,
    inNeonAuthOnly,
    roleMismatches,
  };
}
