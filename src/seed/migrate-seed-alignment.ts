import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

/**
 * Seed alignment migration.
 * Adds indexes for the key lookup patterns used by seed/upsert scripts.
 */
async function migrate() {
  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_seed_modules_subject_title
    ON modules(subject_id, title);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_seed_lessons_module_title
    ON lessons(module_id, title);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_seed_quizzes_module_title
    ON quizzes(module_id, title);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_seed_quiz_questions_quiz_id
    ON quiz_questions(quiz_id);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_seed_assignments_module_title
    ON assignments(module_id, title);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_seed_module_checklist_items_module_title
    ON module_checklist_items(module_id, title);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_seed_assessments_type_module_title
    ON assessments(type, module_id, title);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_seed_question_bank_source_reference
    ON question_bank_items(source, source_reference);
  `);

  console.log("Migration complete: seed alignment indexes created.");
}

migrate().catch((error) => {
  console.error("Migration failed", error);
  process.exit(1);
});
