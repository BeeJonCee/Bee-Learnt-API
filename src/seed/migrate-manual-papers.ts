import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

export async function migrate() {
  // ── Extend assessment_status enum ─────────────────────────────────────────
  await db.execute(sql`
    DO $$ BEGIN
      ALTER TYPE assessment_status ADD VALUE IF NOT EXISTS 'closed';
    EXCEPTION WHEN others THEN NULL; END $$;
  `);
  await db.execute(sql`
    DO $$ BEGIN
      ALTER TYPE assessment_status ADD VALUE IF NOT EXISTS 'marking';
    EXCEPTION WHEN others THEN NULL; END $$;
  `);
  await db.execute(sql`
    DO $$ BEGIN
      ALTER TYPE assessment_status ADD VALUE IF NOT EXISTS 'released';
    EXCEPTION WHEN others THEN NULL; END $$;
  `);

  // ── Extend attempt_status enum ────────────────────────────────────────────
  await db.execute(sql`
    DO $$ BEGIN
      ALTER TYPE attempt_status ADD VALUE IF NOT EXISTS 'released';
    EXCEPTION WHEN others THEN NULL; END $$;
  `);

  // ── Extend assessments table ──────────────────────────────────────────────
  await db.execute(sql`
    ALTER TABLE assessments
      ADD COLUMN IF NOT EXISTS strict_mode      boolean NOT NULL DEFAULT false,
      ADD COLUMN IF NOT EXISTS paper_type       varchar(20) DEFAULT 'weekly',
      ADD COLUMN IF NOT EXISTS is_manual_paper  boolean NOT NULL DEFAULT false;
  `);

  // ── Extend assessment_sections table ──────────────────────────────────────
  await db.execute(sql`
    ALTER TABLE assessment_sections
      ADD COLUMN IF NOT EXISTS label       varchar(10),
      ADD COLUMN IF NOT EXISTS total_marks integer,
      ADD COLUMN IF NOT EXISTS strict_mode boolean NOT NULL DEFAULT false;
  `);

  // ── Extend attempt_answers table ──────────────────────────────────────────
  // users.id is uuid PRIMARY KEY in Postgres — FK columns must also be uuid.
  await db.execute(sql`
    ALTER TABLE attempt_answers
      ADD COLUMN IF NOT EXISTS marked_by uuid REFERENCES users(id),
      ADD COLUMN IF NOT EXISTS marked_at timestamptz;
  `);

  // ── Create paper_assignments table ────────────────────────────────────────
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS paper_assignments (
      id            serial PRIMARY KEY,
      assessment_id integer NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
      student_id    uuid    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      assigned_by   uuid    NOT NULL REFERENCES users(id),
      open_at       timestamptz,
      close_at      timestamptz,
      max_attempts  integer NOT NULL DEFAULT 1,
      created_at    timestamptz DEFAULT now(),
      UNIQUE (assessment_id, student_id)
    );
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_paper_assignments_student
    ON paper_assignments(student_id);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_paper_assignments_assessment
    ON paper_assignments(assessment_id);
  `);

  // ── Index for question bank search performance ────────────────────────────
  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_qbi_subject_topic_type
    ON question_bank_items(subject_id, topic_id, type);
  `);

  console.log("Migration complete: manual-papers extension applied.");
}

// Auto-run when executed directly
const isMain = process.argv[1]?.replace(/\\/g, "/").includes("seed/migrate-");
if (isMain) {
  migrate().catch((error) => {
    console.error("Migration failed", error);
    process.exit(1);
  });
}
