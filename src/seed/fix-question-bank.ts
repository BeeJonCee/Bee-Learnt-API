import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

async function fixQuestionBank() {
  console.log("Adding missing columns to question_bank_items...");

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
      CREATE TYPE quiz_difficulty AS ENUM ('easy', 'medium', 'hard', 'adaptive');
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);
  
  await db.execute(sql`
    ALTER TABLE public.question_bank_items
      ADD COLUMN IF NOT EXISTS type quiz_question_type,
      ADD COLUMN IF NOT EXISTS difficulty quiz_difficulty,
      ADD COLUMN IF NOT EXISTS topic_id integer,
      ADD COLUMN IF NOT EXISTS learning_outcome_id integer,
      ADD COLUMN IF NOT EXISTS nsc_paper_question_id integer;
  `);

  await db.execute(sql`
    UPDATE public.question_bank_items
    SET type = 'multiple_choice'::quiz_question_type
    WHERE type IS NULL;
  `);

  await db.execute(sql`
    UPDATE public.question_bank_items
    SET difficulty = 'medium'::quiz_difficulty
    WHERE difficulty IS NULL;
  `);

  await db.execute(sql`
    ALTER TABLE public.question_bank_items
      ALTER COLUMN type SET DEFAULT 'multiple_choice'::quiz_question_type,
      ALTER COLUMN type SET NOT NULL,
      ALTER COLUMN difficulty SET DEFAULT 'medium'::quiz_difficulty,
      ALTER COLUMN difficulty SET NOT NULL;
  `);

  console.log("Columns added successfully!");
}

fixQuestionBank().catch((error) => {
  console.error("Fix failed", error);
  process.exit(1);
});
