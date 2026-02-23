import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

const QUESTION_TYPES = [
  "multiple_choice",
  "multi_select",
  "true_false",
  "short_answer",
  "essay",
  "long_answer",
  "numeric",
  "matching",
  "ordering",
  "fill_in_blank",
  "code_practical",
] as const;

const ANSWER_FORMATS = [
  "one_word",
  "number",
  "short_sentence",
  "sql_snippet",
  "code_line",
  "paragraph",
  "code_block",
] as const;

export async function migrate() {
  for (const questionType of QUESTION_TYPES) {
    await db.execute(
      sql.raw(`
        DO $$ BEGIN
          ALTER TYPE quiz_question_type ADD VALUE IF NOT EXISTS '${questionType}';
        EXCEPTION WHEN others THEN NULL; END $$;
      `),
    );
  }

  await db.execute(sql`
    ALTER TABLE question_bank_items
      ADD COLUMN IF NOT EXISTS answer_format varchar(32),
      ADD COLUMN IF NOT EXISTS rubric_criteria jsonb DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS practical_config jsonb DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS model_answer text,
      ADD COLUMN IF NOT EXISTS memo text;
  `);

  await db.execute(sql`
    DO $$ BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_qbi_answer_format'
      ) THEN
        ALTER TABLE question_bank_items
        ADD CONSTRAINT chk_qbi_answer_format
        CHECK (
          answer_format IS NULL OR
          answer_format IN (
            'one_word',
            'number',
            'short_sentence',
            'sql_snippet',
            'code_line',
            'paragraph',
            'code_block'
          )
        );
      END IF;
    END $$;
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_qbi_type_difficulty
    ON question_bank_items(type, difficulty);
  `);

  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS idx_qbi_answer_format
    ON question_bank_items(answer_format);
  `);

  console.log(
    `Migration complete: question-bank types + metadata applied (${ANSWER_FORMATS.length} answer formats).`,
  );
}

const isMain = process.argv[1]?.replace(/\\/g, "/").includes("seed/migrate-");
if (isMain) {
  migrate().catch((error) => {
    console.error("Migration failed", error);
    process.exit(1);
  });
}
