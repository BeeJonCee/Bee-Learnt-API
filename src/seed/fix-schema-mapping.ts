import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { db as authDb } from "../core/database/neon-auth-db.js";

/**
 * Fix schema mapping between legacy public."user" and neondb "user".
 *
 * Architecture:
 * - beelearnt DB (appDb/db): public.users, public.roles, etc.
 * - neondb DB (authDb): public.user, public.account, public.session, etc.
 *
 * This script is safe to run multiple times:
 * - Copies any rows from legacy public."user" in beelearnt -> neondb "user" (via authDb)
 * - Removes stale FKs on public.users that pointed to a non-existent neon_auth schema
 *
 * NOTE: Cross-database FKs are impossible, so users.id is a standalone uuid PK.
 * Consistency between beelearnt.users and neondb.user is maintained at the application layer.
 */

async function run() {
  if (!authDb) {
    console.log("⚠️  NEON_AUTH_DATABASE_URL not set. Skipping neondb operations.");
    console.log("   Only cleaning up stale FKs on beelearnt.users.\n");
  }

  // 1) If legacy public."user" table exists in beelearnt DB, copy rows to neondb.
  if (authDb) {
    const legacyUserTable = await db.execute(sql`
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = 'user'
    `);

    if (legacyUserTable.rows.length > 0) {
      console.log("📋 Found legacy public.user table in beelearnt DB. Copying to neondb...");

      const legacyUsers = await db.execute(sql`
        SELECT id, name, email, "emailVerified", image, "createdAt", "updatedAt", role, banned, "banReason", "banExpires"
        FROM public."user"
      `);

      let copied = 0;
      for (const user of legacyUsers.rows as any[]) {
        try {
          await authDb.execute(sql`
            INSERT INTO "user" (id, name, email, "emailVerified", image, "createdAt", "updatedAt", role, banned, "banReason", "banExpires")
            VALUES (
              ${user.id}, ${user.name}, ${user.email}, ${user.emailVerified},
              ${user.image}, ${user.createdAt}, ${user.updatedAt}, ${user.role},
              ${user.banned}, ${user.banReason}, ${user.banExpires}
            )
            ON CONFLICT (id) DO NOTHING;
          `);
          copied++;
        } catch (e) {
          console.log(`   ⚠️  Could not copy user ${user.email || user.id}`);
        }
      }
      console.log(`   ✅ Copied ${copied}/${legacyUsers.rows.length} users to neondb`);
    } else {
      console.log("ℹ️  No legacy public.user table found in beelearnt DB.");
    }
  }

  // 2) Remove any stale FKs on public.users that reference neon_auth schema
  //    (which doesn't exist — neon auth tables are in a separate database).
  console.log("\n📋 Checking for stale foreign keys on beelearnt.users...");

  const fks = await db.execute<{
    conname: string;
    ref_schema: string;
    ref_table: string;
  }>(sql`
    SELECT
      c.conname::text as conname,
      nsf.nspname::text as ref_schema,
      rf.relname::text as ref_table
    FROM pg_constraint c
    JOIN pg_class rl ON rl.oid = c.conrelid
    JOIN pg_namespace nsl ON nsl.oid = rl.relnamespace
    JOIN pg_class rf ON rf.oid = c.confrelid
    JOIN pg_namespace nsf ON nsf.oid = rf.relnamespace
    WHERE c.contype = 'f'
      AND nsl.nspname = 'public'
      AND rl.relname = 'users';
  `);

  let droppedCount = 0;
  for (const fk of fks.rows) {
    // Drop any FK pointing to neon_auth schema (stale) or to public."user" (legacy)
    const isStale =
      fk.ref_schema === "neon_auth" ||
      (fk.ref_schema === "public" && fk.ref_table === "user");

    if (isStale) {
      console.log(`   Dropping stale FK: ${fk.conname} -> ${fk.ref_schema}.${fk.ref_table}`);
      await db.execute(sql.raw(`ALTER TABLE public.users DROP CONSTRAINT IF EXISTS "${fk.conname}";`));
      droppedCount++;
    }
  }

  if (droppedCount === 0) {
    console.log("   ✅ No stale FKs found.");
  } else {
    console.log(`   ✅ Dropped ${droppedCount} stale FK(s).`);
  }

  console.log("\nSchema mapping fix complete.");
  console.log("\n💡 Note: Cross-database FKs are not possible.");
  console.log("   beelearnt.users.id and neondb.user.id are kept in sync at the application layer.");
}

run().catch((error) => {
  console.error("Schema mapping fix failed:", error);
  process.exit(1);
});
