import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

export async function migrate() {
  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE content_audience AS ENUM ('ALL', 'STUDENT', 'PARENT', 'ADMIN', 'TUTOR');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`ALTER TYPE content_audience ADD VALUE IF NOT EXISTS 'TUTOR';`);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS announcements (
      id serial PRIMARY KEY,
      title varchar(160) NOT NULL,
      body text NOT NULL,
      audience content_audience NOT NULL DEFAULT 'ALL',
      pinned boolean NOT NULL DEFAULT false,
      published_at timestamptz NOT NULL DEFAULT now(),
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS events (
      id serial PRIMARY KEY,
      title varchar(160) NOT NULL,
      description text NOT NULL,
      start_at timestamptz NOT NULL,
      end_at timestamptz,
      all_day boolean NOT NULL DEFAULT false,
      location text,
      audience content_audience NOT NULL DEFAULT 'ALL',
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  console.log("Migration complete: announcements and events tables created.");
}

// Auto-run when executed directly (e.g. `tsx src/seed/migrate-announcements-events.ts`)
const isMain = process.argv[1]?.replace(/\\/g, "/").includes("seed/migrate-");
if (isMain) {
  migrate().catch((error) => {
    console.error("Migration failed", error);
    process.exit(1);
  });
}
