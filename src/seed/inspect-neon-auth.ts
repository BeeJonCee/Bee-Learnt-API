import "dotenv/config";
import { sql } from "drizzle-orm";
import { db as authDb } from "../core/database/neon-auth-db.js";

async function tableExists(tableName: string) {
  if (!authDb) return false;

  const result = await authDb.execute<{ exists: boolean }>(sql`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = 'neon_auth'
        AND table_name = ${tableName}
    ) AS exists
  `);

  return Boolean(result.rows[0]?.exists);
}

async function inspectNeonAuth() {
  console.log("Inspecting Neon Auth database (neondb.neon_auth)");

  if (!authDb) {
    console.error("NEON_AUTH_DATABASE_URL is not set.");
    process.exit(1);
  }

  const tableRows = await authDb.execute<{ table_name: string }>(sql`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = 'neon_auth'
    ORDER BY table_name
  `);

  if (tableRows.rows.length === 0) {
    console.log("No tables found in neon_auth schema.");
    return;
  }

  console.log("\nTables:");
  for (const row of tableRows.rows) {
    console.log(`  - ${row.table_name}`);
  }

  const users = await authDb.execute<{
    id: string;
    email: string;
    name: string | null;
    role: string | null;
    emailVerified: boolean;
    banned: boolean;
    createdAt: Date;
  }>(sql`
    SELECT
      id::text,
      email,
      name,
      role,
      "emailVerified",
      banned,
      "createdAt"
    FROM neon_auth."user"
    ORDER BY "createdAt" DESC
    LIMIT 10
  `);

  console.log(`\nLatest users (${users.rows.length}):`);
  for (const user of users.rows) {
    console.log(
      `  - ${user.email} id=${user.id} role=${user.role ?? "null"} verified=${user.emailVerified} banned=${user.banned}`,
    );
  }

  const accounts = await authDb.execute<{
    id: string;
    userId: string;
    providerId: string;
    accountId: string;
    email: string | null;
  }>(sql`
    SELECT
      a.id::text,
      a."userId"::text AS "userId",
      a."providerId",
      a."accountId",
      u.email
    FROM neon_auth.account a
    LEFT JOIN neon_auth."user" u ON a."userId" = u.id
    ORDER BY a."createdAt" DESC
    LIMIT 10
  `);

  console.log(`\nLatest accounts (${accounts.rows.length}):`);
  for (const account of accounts.rows) {
    console.log(
      `  - provider=${account.providerId} user=${account.email ?? "unknown"} accountId=${account.accountId}`,
    );
  }

  if (await tableExists("member")) {
    const members = await authDb.execute<{
      id: string;
      userId: string;
      organizationId: string;
      role: string;
      email: string | null;
    }>(sql`
      SELECT
        m.id::text,
        m."userId"::text AS "userId",
        m."organizationId"::text AS "organizationId",
        m.role,
        u.email
      FROM neon_auth.member m
      LEFT JOIN neon_auth."user" u ON m."userId" = u.id
      ORDER BY m."createdAt" DESC
      LIMIT 10
    `);

    console.log(`\nLatest members (${members.rows.length}):`);
    for (const member of members.rows) {
      console.log(
        `  - user=${member.email ?? member.userId} org=${member.organizationId} role=${member.role}`,
      );
    }
  } else {
    console.log("\nmember table not found in neon_auth schema.");
  }
}

inspectNeonAuth()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Inspection failed:", error);
    process.exit(1);
  });
