import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

async function migrate() {
  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE qb_source AS ENUM (
        'manual',
        'nsc_past_paper',
        'exemplar',
        'textbook',
        'ai_generated',
        'imported'
      );
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE assessment_type AS ENUM (
        'quiz',
        'test',
        'exam',
        'practice',
        'nsc_simulation',
        'diagnostic'
      );
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE assessment_status AS ENUM ('draft', 'published', 'archived');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE attempt_status AS ENUM (
        'in_progress',
        'submitted',
        'timed_out',
        'graded',
        'reviewed'
      );
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS question_bank_items (
      id serial PRIMARY KEY,
      subject_id integer NOT NULL REFERENCES subjects(id),
      module_id integer REFERENCES modules(id),
      topic_id integer,
      learning_outcome_id integer,
      nsc_paper_question_id integer,
      type quiz_question_type NOT NULL,
      difficulty quiz_difficulty NOT NULL DEFAULT 'medium',
      question_text text NOT NULL,
      question_html text,
      image_url text,
      options jsonb,
      correct_answer jsonb,
      explanation text,
      solution_steps jsonb NOT NULL DEFAULT '[]'::jsonb,
      points integer NOT NULL DEFAULT 1,
      time_limit_seconds integer,
      source qb_source NOT NULL DEFAULT 'manual',
      source_reference varchar(200),
      tags jsonb NOT NULL DEFAULT '[]'::jsonb,
      language varchar(10) NOT NULL DEFAULT 'en',
      is_active boolean NOT NULL DEFAULT true,
      created_by uuid REFERENCES users(id),
      reviewed_by uuid REFERENCES users(id),
      reviewed_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  // Backfill columns for existing databases
  await db.execute(sql`
    ALTER TABLE question_bank_items
      ADD COLUMN IF NOT EXISTS type quiz_question_type,
      ADD COLUMN IF NOT EXISTS difficulty quiz_difficulty,
      ADD COLUMN IF NOT EXISTS topic_id integer,
      ADD COLUMN IF NOT EXISTS learning_outcome_id integer,
      ADD COLUMN IF NOT EXISTS nsc_paper_question_id integer;
  `);

  await db.execute(sql`
    UPDATE question_bank_items
    SET type = 'multiple_choice'::quiz_question_type
    WHERE type IS NULL;
  `);

  await db.execute(sql`
    UPDATE question_bank_items
    SET difficulty = 'medium'::quiz_difficulty
    WHERE difficulty IS NULL;
  `);

  await db.execute(sql`
    ALTER TABLE question_bank_items
      ALTER COLUMN type SET DEFAULT 'multiple_choice'::quiz_question_type,
      ALTER COLUMN type SET NOT NULL,
      ALTER COLUMN difficulty SET DEFAULT 'medium'::quiz_difficulty,
      ALTER COLUMN difficulty SET NOT NULL;
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_question_bank_items_subject
    ON question_bank_items(subject_id);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_question_bank_items_source_ref
    ON question_bank_items(source, source_reference);
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS assessments (
      id serial PRIMARY KEY,
      title varchar(200) NOT NULL,
      description text,
      type assessment_type NOT NULL,
      status assessment_status NOT NULL DEFAULT 'draft',
      subject_id integer NOT NULL REFERENCES subjects(id),
      grade integer,
      module_id integer REFERENCES modules(id),
      time_limit_minutes integer,
      total_marks integer,
      pass_mark integer,
      max_attempts integer,
      shuffle_questions boolean NOT NULL DEFAULT false,
      shuffle_options boolean NOT NULL DEFAULT false,
      show_results_immediately boolean NOT NULL DEFAULT true,
      show_correct_answers boolean NOT NULL DEFAULT true,
      show_explanations boolean NOT NULL DEFAULT true,
      available_from timestamptz,
      available_until timestamptz,
      instructions text,
      created_by uuid REFERENCES users(id),
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_assessments_subject_status
    ON assessments(subject_id, status);
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS assessment_sections (
      id serial PRIMARY KEY,
      assessment_id integer NOT NULL REFERENCES assessments(id),
      title varchar(160),
      instructions text,
      "order" integer NOT NULL,
      time_limit_minutes integer
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_assessment_sections_assessment
    ON assessment_sections(assessment_id);
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS assessment_questions (
      id serial PRIMARY KEY,
      assessment_id integer NOT NULL REFERENCES assessments(id),
      section_id integer REFERENCES assessment_sections(id),
      question_bank_item_id integer NOT NULL REFERENCES question_bank_items(id),
      "order" integer NOT NULL,
      override_points integer
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_assessment_questions_assessment
    ON assessment_questions(assessment_id, "order");
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS assessment_attempts (
      id uuid PRIMARY KEY,
      assessment_id integer NOT NULL REFERENCES assessments(id),
      user_id uuid NOT NULL REFERENCES users(id),
      status attempt_status NOT NULL DEFAULT 'in_progress',
      started_at timestamptz NOT NULL DEFAULT now(),
      submitted_at timestamptz,
      total_score integer,
      max_score integer,
      percentage integer,
      time_spent_seconds integer,
      feedback text,
      graded_by uuid REFERENCES users(id),
      graded_at timestamptz,
      metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_assessment_attempts_user
    ON assessment_attempts(user_id, assessment_id);
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS attempt_answers (
      id serial PRIMARY KEY,
      attempt_id uuid NOT NULL REFERENCES assessment_attempts(id),
      assessment_question_id integer NOT NULL REFERENCES assessment_questions(id),
      question_bank_item_id integer NOT NULL REFERENCES question_bank_items(id),
      answer jsonb,
      is_correct boolean,
      score integer,
      max_score integer,
      time_taken_seconds integer,
      marker_comment text,
      answered_at timestamptz
    );
  `);

  // Allow idempotent upsert from the API layer.
  await db.execute(sql`
    CREATE UNIQUE INDEX IF NOT EXISTS ux_attempt_answers_attempt_question
    ON attempt_answers(attempt_id, assessment_question_id);
  `);

  console.log("Migration complete: question bank + assessment engine tables created.");
}

migrate().catch((error) => {
  console.error("Migration failed", error);
  process.exit(1);
});
