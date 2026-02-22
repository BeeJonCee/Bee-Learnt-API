import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

/**
 * Creates the assignment_submissions table.
 * Safe to run multiple times (uses IF NOT EXISTS).
 */
export async function migrate() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS assignment_submissions (
      id              SERIAL PRIMARY KEY,
      assignment_id   INTEGER     NOT NULL REFERENCES assignments(id),
      user_id         UUID        NOT NULL REFERENCES users(id),
      submission_text TEXT,
      submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      rubric_id       INTEGER REFERENCES rubrics(id),
      rubric_scores   JSONB,
      total_score     INTEGER,
      max_score       INTEGER,
      feedback        TEXT,
      graded_at       TIMESTAMPTZ,
      graded_by       UUID REFERENCES users(id),
      CONSTRAINT assignment_submissions_user_idx UNIQUE (assignment_id, user_id)
    );
  `);

  console.log("✓ assignment_submissions table ready");
}

migrate()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
