import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

/**
 * Full DB reset for the app schema.
 * Drops all public tables and enum types so migrations can rebuild cleanly.
 */
export async function reset() {
  await db.execute(sql`
    DO $$
    DECLARE
      table_record record;
      type_record record;
    BEGIN
      FOR table_record IN
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public'
      LOOP
        EXECUTE format('DROP TABLE IF EXISTS public.%I CASCADE', table_record.tablename);
      END LOOP;

      FOR type_record IN
        SELECT t.typname
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'public' AND t.typtype = 'e'
      LOOP
        EXECUTE format('DROP TYPE IF EXISTS public.%I CASCADE', type_record.typname);
      END LOOP;
    END $$;
  `);

  console.log("Database reset complete.");
}

const entrypoint = process.argv[1]?.replace(/\\/g, "/") ?? "";
const isMain = /\/seed\/reset-db(\.js|\.ts)?$/.test(entrypoint);

if (isMain) {
  reset().catch((error) => {
    console.error("Reset failed", error);
    process.exit(1);
  });
}
