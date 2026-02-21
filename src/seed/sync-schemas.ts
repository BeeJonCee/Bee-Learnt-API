import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { db as authDb } from "../core/database/neon-auth-db.js";
import {
  syncAllUsersToNeonAuth,
  verifySchemaConsistency,
} from "../shared/utils/schema-sync.js";

async function tableExistsInSchema(database: any, schema: string, tableName: string) {
  const result = await database.execute(sql`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = ${schema}
        AND table_name = ${tableName}
    ) AS exists
  `);

  const rows = result.rows as Array<{ exists?: boolean }>;
  return Boolean(rows[0]?.exists);
}

async function checkDatabases(): Promise<boolean> {
  console.log("Checking database connections...");

  try {
    await db.execute(sql`SELECT 1`);
    console.log("  OK beelearnt database connected");
  } catch (error) {
    console.error("  FAIL beelearnt database connection failed");
    return false;
  }

  if (!authDb) {
    console.error("  FAIL Neon Auth database is not configured");
    return false;
  }

  try {
    await authDb.execute(sql`SELECT 1`);
    console.log("  OK Neon Auth database connected");
  } catch (error) {
    console.error("  FAIL Neon Auth database connection failed");
    return false;
  }

  const appTables = ["users", "roles"];
  for (const table of appTables) {
    const exists = await tableExistsInSchema(db, "public", table);
    if (!exists) {
      console.error(`  FAIL Missing beelearnt.public.${table}`);
      return false;
    }
    console.log(`  OK beelearnt.public.${table}`);
  }

  const authTables = ["user", "account"];
  for (const table of authTables) {
    const exists = await tableExistsInSchema(authDb, "neon_auth", table);
    if (!exists) {
      console.error(`  FAIL Missing neondb.neon_auth.${table}`);
      return false;
    }
    console.log(`  OK neondb.neon_auth.${table}`);
  }

  const memberExists = await tableExistsInSchema(authDb, "neon_auth", "member");
  console.log(
    memberExists
      ? "  OK neondb.neon_auth.member"
      : "  WARN neondb.neon_auth.member not found (organization features disabled)",
  );

  return true;
}

async function displayStats() {
  const appUsersCount = await db.execute<{ count: string }>(
    sql`SELECT COUNT(*)::text AS count FROM users`,
  );
  const appCount = appUsersCount.rows[0]?.count ?? "0";
  console.log(`beelearnt.public.users:           ${appCount}`);

  if (!authDb) return;

  const neonUsersCount = await authDb.execute<{ count: string }>(
    sql`SELECT COUNT(*)::text AS count FROM neon_auth."user"`,
  );
  const neonAccountsCount = await authDb.execute<{ count: string }>(sql`
    SELECT COUNT(*)::text AS count
    FROM neon_auth.account
    WHERE password IS NOT NULL
      AND "providerId" IN ('credential', 'email')
  `);

  console.log(`neondb.neon_auth.user:            ${neonUsersCount.rows[0]?.count ?? "0"}`);
  console.log(
    `neondb.neon_auth.account (pwd):   ${neonAccountsCount.rows[0]?.count ?? "0"}`,
  );

  try {
    const neonMembersCount = await authDb.execute<{ count: string }>(
      sql`SELECT COUNT(*)::text AS count FROM neon_auth.member`,
    );
    console.log(`neondb.neon_auth.member:          ${neonMembersCount.rows[0]?.count ?? "0"}`);
  } catch {
    console.log("neondb.neon_auth.member:          n/a");
  }
}

async function main() {
  console.log("BeeLearnt schema sync");
  console.log("========================================");

  const dbsOk = await checkDatabases();
  if (!dbsOk) {
    process.exit(1);
  }

  console.log("\nCurrent stats");
  await displayStats();

  console.log("\nChecking consistency...");
  const initial = await verifySchemaConsistency();
  if (initial.consistent) {
    console.log("Schema consistency OK");
    return;
  }

  console.log(`Found ${initial.mismatches.length} mismatches. Starting sync...`);
  const result = await syncAllUsersToNeonAuth();
  console.log(`Sync result: synced=${result.synced} failed=${result.failed}`);

  const finalCheck = await verifySchemaConsistency();
  if (finalCheck.consistent) {
    console.log("Schema consistency OK after sync");
  } else {
    console.log(`Remaining mismatches: ${finalCheck.mismatches.length}`);
    for (const mismatch of finalCheck.mismatches) {
      console.log(`  - ${mismatch.issue}`);
    }
  }

  console.log("\nFinal stats");
  await displayStats();
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Sync failed:", error);
    process.exit(1);
  });
