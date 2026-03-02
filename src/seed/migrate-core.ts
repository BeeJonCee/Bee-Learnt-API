import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

/**
 * Core migration: creates enums + application tables in the beelearnt database.
 *
 * NOTE: Neon Auth tables (user, account, session, member, organization) live
 * in a separate "neondb" database and are auto-created by Neon Auth.
 * This script does NOT create or manage those tables.
 * The users.id column is a standalone uuid PK (not a cross-DB FK).
 */

export async function migrate() {
  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE role AS ENUM ('STUDENT', 'PARENT', 'ADMIN', 'TUTOR');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  // Existing databases may have been created before TUTOR was introduced.
  await db.execute(sql`ALTER TYPE role ADD VALUE IF NOT EXISTS 'TUTOR';`);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE lesson_type AS ENUM ('text', 'video', 'diagram', 'pdf');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE resource_type AS ENUM ('pdf', 'link', 'video', 'diagram');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE quiz_difficulty AS ENUM ('easy', 'medium', 'hard', 'adaptive');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE quiz_question_type AS ENUM ('multiple_choice', 'short_answer', 'essay');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE assignment_priority AS ENUM ('low', 'medium', 'high');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE assignment_status AS ENUM ('todo', 'in_progress', 'submitted', 'graded');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE badge_rule AS ENUM ('lesson_streak', 'quiz_mastery', 'assignment_finisher', 'study_time');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  // -- Application tables (beelearnt database) --

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS roles (
      id serial PRIMARY KEY,
      name role NOT NULL UNIQUE,
      description text,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY,
      name varchar(120) NOT NULL,
      email varchar(255) NOT NULL UNIQUE,
      password_hash text,
      image text,
      role_id integer NOT NULL REFERENCES roles(id),
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      last_login_at timestamptz
    );
  `);

  // Backfill newer auth/profile columns on existing databases.
  await db.execute(sql`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS phone varchar(30),
      ADD COLUMN IF NOT EXISTS email_verified_at timestamptz,
      ADD COLUMN IF NOT EXISTS phone_verified_at timestamptz,
      ADD COLUMN IF NOT EXISTS login_email_alert_enabled boolean NOT NULL DEFAULT true,
      ADD COLUMN IF NOT EXISTS login_sms_alert_enabled boolean NOT NULL DEFAULT false,
      ADD COLUMN IF NOT EXISTS last_login_at timestamptz;
  `);

  await db.execute(sql`
    CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique_idx
    ON users(phone)
    WHERE phone IS NOT NULL;
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS email_verification_codes (
      id serial PRIMARY KEY,
      email text NOT NULL,
      code_hash text NOT NULL,
      expires_at timestamptz NOT NULL,
      consumed_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_email_verification_codes_email
    ON email_verification_codes(email);
  `);

  // Unified verification/OTP table used by /api/auth/verification/* endpoints.
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS auth_verification_codes (
      id serial PRIMARY KEY,
      user_id uuid REFERENCES users(id),
      channel varchar(16) NOT NULL,
      purpose varchar(40) NOT NULL,
      target text NOT NULL,
      code_hash text NOT NULL,
      expires_at timestamptz NOT NULL,
      attempts integer NOT NULL DEFAULT 0,
      last_sent_at timestamptz NOT NULL DEFAULT now(),
      consumed_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_auth_verification_codes_channel_target_created
    ON auth_verification_codes(channel, target, created_at DESC);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_auth_verification_codes_user_id
    ON auth_verification_codes(user_id);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_auth_verification_codes_active
    ON auth_verification_codes(channel, target, expires_at)
    WHERE consumed_at IS NULL;
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS parent_student_links (
      id serial PRIMARY KEY,
      parent_id uuid NOT NULL REFERENCES users(id),
      student_id uuid NOT NULL REFERENCES users(id),
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS student_profiles (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL UNIQUE REFERENCES users(id),
      grade integer NOT NULL,
      school varchar(200),
      date_of_birth timestamptz,
      guardian_name varchar(120),
      guardian_contact varchar(80),
      emergency_contact varchar(80),
      medical_info text,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS parent_profiles (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL UNIQUE REFERENCES users(id),
      occupation varchar(120),
      phone_number varchar(40),
      address text,
      emergency_contact varchar(80),
      preferences jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS subjects (
      id serial PRIMARY KEY,
      name varchar(120) NOT NULL,
      description text,
      min_grade integer NOT NULL,
      max_grade integer NOT NULL,
      code varchar(20),
      caps_document_url text,
      curriculum_id integer,
      icon_url text,
      color varchar(7),
      is_active boolean NOT NULL DEFAULT true,
      deleted_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS modules (
      id serial PRIMARY KEY,
      subject_id integer NOT NULL REFERENCES subjects(id),
      title varchar(160) NOT NULL,
      description text,
      grade integer NOT NULL,
      "order" integer NOT NULL,
      caps_tags jsonb NOT NULL DEFAULT '[]'::jsonb,
      term_number integer,
      topic_id integer,
      estimated_minutes integer,
      prerequisite_module_id integer,
      is_active boolean NOT NULL DEFAULT true,
      deleted_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS lessons (
      id serial PRIMARY KEY,
      module_id integer NOT NULL REFERENCES modules(id),
      title varchar(160) NOT NULL,
      content text,
      type lesson_type NOT NULL,
      video_url text,
      diagram_url text,
      pdf_url text,
      "order" integer NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS lesson_resources (
      id serial PRIMARY KEY,
      lesson_id integer NOT NULL REFERENCES lessons(id),
      title varchar(160) NOT NULL,
      type resource_type NOT NULL,
      url text NOT NULL,
      tags jsonb NOT NULL DEFAULT '[]'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS progress_tracking (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id),
      lesson_id integer REFERENCES lessons(id),
      module_id integer REFERENCES modules(id),
      completed boolean NOT NULL DEFAULT false,
      time_spent_minutes integer NOT NULL DEFAULT 0,
      last_accessed_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS assignments (
      id serial PRIMARY KEY,
      module_id integer NOT NULL REFERENCES modules(id),
      lesson_id integer REFERENCES lessons(id),
      title varchar(160) NOT NULL,
      description text,
      due_date timestamptz NOT NULL,
      priority assignment_priority NOT NULL DEFAULT 'medium',
      status assignment_status NOT NULL DEFAULT 'todo',
      grade integer NOT NULL,
      reminders jsonb NOT NULL DEFAULT '[]'::jsonb,
      created_by uuid REFERENCES users(id),
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS module_checklist_items (
      id serial PRIMARY KEY,
      module_id integer NOT NULL REFERENCES modules(id),
      title varchar(160) NOT NULL,
      "order" integer NOT NULL,
      required boolean NOT NULL DEFAULT true
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS checklist_progress (
      id serial PRIMARY KEY,
      item_id integer NOT NULL REFERENCES module_checklist_items(id),
      user_id uuid NOT NULL REFERENCES users(id),
      completed boolean NOT NULL DEFAULT false,
      completed_at timestamptz
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS quizzes (
      id serial PRIMARY KEY,
      module_id integer NOT NULL REFERENCES modules(id),
      title varchar(160) NOT NULL,
      description text,
      difficulty quiz_difficulty NOT NULL DEFAULT 'medium',
      source varchar(40) NOT NULL DEFAULT 'manual',
      caps_tags jsonb NOT NULL DEFAULT '[]'::jsonb,
      reveal_correct_answers boolean NOT NULL DEFAULT true,
      reveal_to_parents boolean NOT NULL DEFAULT true,
      created_by uuid REFERENCES users(id),
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  // Keep quiz visibility flags in sync with the current drizzle schema.
  await db.execute(sql`
    ALTER TABLE quizzes
      ADD COLUMN IF NOT EXISTS reveal_correct_answers boolean NOT NULL DEFAULT true,
      ADD COLUMN IF NOT EXISTS reveal_to_parents boolean NOT NULL DEFAULT true;
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS quiz_questions (
      id serial PRIMARY KEY,
      quiz_id integer NOT NULL REFERENCES quizzes(id),
      type quiz_question_type NOT NULL,
      question_text text NOT NULL,
      options jsonb,
      correct_answer text,
      explanation text,
      points integer NOT NULL DEFAULT 1,
      difficulty quiz_difficulty DEFAULT 'medium',
      topic_id integer,
      question_bank_item_id integer,
      tags jsonb DEFAULT '[]'::jsonb,
      image_url text,
      time_limit_seconds integer
    );
  `);

  await db.execute(sql`
    ALTER TABLE quiz_questions
      ADD COLUMN IF NOT EXISTS difficulty quiz_difficulty DEFAULT 'medium',
      ADD COLUMN IF NOT EXISTS topic_id integer,
      ADD COLUMN IF NOT EXISTS question_bank_item_id integer,
      ADD COLUMN IF NOT EXISTS tags jsonb DEFAULT '[]'::jsonb,
      ADD COLUMN IF NOT EXISTS image_url text,
      ADD COLUMN IF NOT EXISTS time_limit_seconds integer;
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS quiz_attempts (
      id serial PRIMARY KEY,
      quiz_id integer NOT NULL REFERENCES quizzes(id),
      user_id uuid NOT NULL REFERENCES users(id),
      score integer NOT NULL,
      max_score integer NOT NULL,
      feedback text,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS quiz_answers (
      id serial PRIMARY KEY,
      attempt_id integer NOT NULL REFERENCES quiz_attempts(id),
      question_id integer NOT NULL REFERENCES quiz_questions(id),
      answer text,
      is_correct boolean NOT NULL DEFAULT false,
      score integer NOT NULL DEFAULT 0
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS badges (
      id serial PRIMARY KEY,
      name varchar(120) NOT NULL,
      description text,
      rule_key badge_rule NOT NULL,
      criteria jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS user_badges (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id),
      badge_id integer NOT NULL REFERENCES badges(id),
      awarded_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS study_sessions (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id),
      started_at timestamptz NOT NULL,
      ended_at timestamptz,
      duration_minutes integer NOT NULL DEFAULT 0,
      source varchar(40) NOT NULL DEFAULT 'timer'
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS streaks (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id),
      current_streak integer NOT NULL DEFAULT 0,
      longest_streak integer NOT NULL DEFAULT 0,
      last_study_date timestamptz,
      weekly_minutes integer NOT NULL DEFAULT 0,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS notifications (
      id serial PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id),
      type varchar(80) NOT NULL,
      title varchar(160) NOT NULL,
      message text,
      read_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id serial PRIMARY KEY,
      actor_id uuid REFERENCES users(id),
      action varchar(120) NOT NULL,
      entity varchar(120) NOT NULL,
      entity_id integer,
      details jsonb NOT NULL DEFAULT '{}'::jsonb,
      ip_address varchar(64),
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  console.log("Migration complete: core tables created in beelearnt database.");
}

// Auto-run when executed directly (e.g. `tsx src/seed/migrate-core.ts`)
const isMain = process.argv[1]?.replace(/\\/g, "/").includes("seed/migrate-");
if (isMain) {
  migrate().catch((error) => {
    console.error("Migration failed", error);
    process.exit(1);
  });
}
