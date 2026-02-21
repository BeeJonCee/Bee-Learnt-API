import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

async function migrate() {
  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE module_access_status AS ENUM ('pending', 'unlocked');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS module_access_codes (
      id serial PRIMARY KEY,
      module_id integer NOT NULL REFERENCES modules(id),
      code_hash text NOT NULL,
      active boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS user_module_selections (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id),
      module_id integer NOT NULL REFERENCES modules(id),
      status module_access_status NOT NULL DEFAULT 'pending',
      selected_at timestamptz NOT NULL DEFAULT now(),
      unlocked_at timestamptz,
      CONSTRAINT user_module_unique UNIQUE (user_id, module_id)
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS lesson_notes (
      id serial PRIMARY KEY,
      lesson_id integer NOT NULL REFERENCES lessons(id),
      user_id uuid NOT NULL REFERENCES users(id),
      content text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  console.log("Migration complete: onboarding and lesson notes tables created.");
}

migrate().catch((error) => {
  console.error("Migration failed", error);
  process.exit(1);
});
