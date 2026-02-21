import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

/**
 * Migration script to create the subject_resources table.
 * Stores grade-level resources (textbooks, guides, data files) not tied to a specific lesson.
 */
async function migrate() {
  console.log("Starting subject_resources migration...");

  // Create enum
  await db.execute(sql`
    DO $$
    BEGIN
      CREATE TYPE subject_resource_type AS ENUM (
        'textbook',
        'teacher_guide',
        'practical_guide',
        'pat_document',
        'caps_document',
        'learner_data',
        'revision_guide',
        'workbook',
        'tutoring_guide'
      );
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);
  console.log("  + subject_resource_type enum ready");

  // Create table
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS subject_resources (
      id SERIAL PRIMARY KEY,
      subject_id INTEGER NOT NULL REFERENCES subjects(id),
      grade_id INTEGER REFERENCES grades(id),
      title VARCHAR(300) NOT NULL,
      type subject_resource_type NOT NULL,
      file_url TEXT NOT NULL,
      file_path TEXT,
      file_size INTEGER,
      mime_type VARCHAR(60),
      language VARCHAR(20) NOT NULL DEFAULT 'English',
      description TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  console.log("  + subject_resources table ready");

  // Create indexes
  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_subject_resources_subject
    ON subject_resources(subject_id);
  `);
  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_subject_resources_grade
    ON subject_resources(subject_id, grade_id);
  `);
  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_subject_resources_type
    ON subject_resources(type);
  `);
  console.log("  + indexes created");

  console.log("subject_resources migration complete!");
}

migrate().catch((error) => {
  console.error("Migration failed:", error);
  process.exit(1);
});
