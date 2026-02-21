import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

async function migrate() {
  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE learning_pace AS ENUM ('slow', 'steady', 'fast');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE learning_path_status AS ENUM ('active', 'completed', 'dismissed');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE collaboration_room_type AS ENUM ('classroom', 'project', 'discussion', 'breakout');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS learning_profiles (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id),
      strengths jsonb DEFAULT '[]'::jsonb,
      weaknesses jsonb DEFAULT '[]'::jsonb,
      goals jsonb DEFAULT '[]'::jsonb,
      preferred_pace learning_pace NOT NULL DEFAULT 'steady',
      recommended_difficulty quiz_difficulty NOT NULL DEFAULT 'medium',
      last_adaptive_update_at timestamptz,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS learning_path_items (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id),
      module_id integer REFERENCES modules(id),
      lesson_id integer REFERENCES lessons(id),
      title varchar(180) NOT NULL,
      reason text,
      priority integer NOT NULL DEFAULT 1,
      status learning_path_status NOT NULL DEFAULT 'active',
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS accessibility_preferences (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id),
      text_scale integer NOT NULL DEFAULT 100,
      enable_narration boolean NOT NULL DEFAULT false,
      high_contrast boolean NOT NULL DEFAULT false,
      language varchar(12) NOT NULL DEFAULT 'en',
      translation_enabled boolean NOT NULL DEFAULT false,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS collaboration_rooms (
      id serial PRIMARY KEY,
      title varchar(160) NOT NULL,
      type collaboration_room_type NOT NULL,
      owner_id uuid NOT NULL REFERENCES users(id),
      description text,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS collaboration_members (
      id serial PRIMARY KEY,
      room_id integer NOT NULL REFERENCES collaboration_rooms(id),
      user_id uuid NOT NULL REFERENCES users(id),
      role varchar(40) NOT NULL DEFAULT 'member',
      joined_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS collaboration_messages (
      id serial PRIMARY KEY,
      room_id integer NOT NULL REFERENCES collaboration_rooms(id),
      user_id uuid NOT NULL REFERENCES users(id),
      content text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  console.log("Migration complete: advanced learning, accessibility, and collaboration tables created.");
}

migrate().catch((error) => {
  console.error("Migration failed", error);
  process.exit(1);
});
