import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

const tables = [
  "roles",
  "users",
  "subjects",
  "modules",
  "lessons",
  "lesson_resources",
  "assignments",
  "quizzes",
  "quiz_questions",
  "quiz_attempts",
  "quiz_answers",
];

async function run() {
  const tableList = tables.map((name) => `'${name}'`).join(", ");
  const rows = await db.execute(
    sql.raw(`
      SELECT table_name, column_name, data_type, udt_name
      FROM information_schema.columns
      WHERE table_name IN (${tableList})
      ORDER BY table_name, ordinal_position;
    `)
  );

  console.table(rows.rows);
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
