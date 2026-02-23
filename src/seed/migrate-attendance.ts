import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

export async function migrate() {
  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE attendance_status AS ENUM ('present', 'absent', 'late', 'excused');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS attendance_records (
      id serial PRIMARY KEY,
      student_id uuid NOT NULL REFERENCES users(id),
      date timestamptz NOT NULL,
      status attendance_status NOT NULL,
      notes text,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  console.log("Migration complete: attendance_records table created.");
}

// Auto-run when executed directly (e.g. `tsx src/seed/migrate-attendance.ts`)
const isMain = process.argv[1]?.replace(/\\/g, "/").includes("seed/migrate-");
if (isMain) {
  migrate().catch((error) => {
    console.error("Migration failed", error);
    process.exit(1);
  });
}
