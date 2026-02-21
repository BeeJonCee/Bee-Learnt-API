import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

async function migrate() {
  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE study_goal_status AS ENUM ('active', 'completed', 'abandoned', 'overdue');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE study_goal_priority AS ENUM ('low', 'medium', 'high');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    DECLARE
      users_id_type text;
      user_id_sql_type text;
    BEGIN
      SELECT data_type
      INTO users_id_type
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'users'
        AND column_name = 'id'
      LIMIT 1;

      IF users_id_type IS NULL THEN
        RAISE EXCEPTION 'users.id column not found';
      END IF;

      IF users_id_type = 'uuid' THEN
        user_id_sql_type := 'uuid';
      ELSE
        user_id_sql_type := 'text';
      END IF;

      EXECUTE format(
        'CREATE TABLE IF NOT EXISTS study_goals (
          id varchar(64) PRIMARY KEY,
          user_id %s NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title varchar(255) NOT NULL,
          description text,
          target_hours integer NOT NULL,
          current_hours integer NOT NULL DEFAULT 0,
          deadline timestamptz NOT NULL,
          status study_goal_status NOT NULL DEFAULT ''active'',
          priority study_goal_priority NOT NULL DEFAULT ''medium'',
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now()
        )',
        user_id_sql_type
      );
    END $$;
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_study_goals_user_id
    ON study_goals(user_id);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_study_goals_status
    ON study_goals(status);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_study_goals_deadline
    ON study_goals(deadline);
  `);

  console.log("Migration complete: study_goals table created.");
}

migrate().catch((error) => {
  console.error("Migration failed", error);
  process.exit(1);
});
