import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

async function checkColumns() {
  console.log("Checking question_bank_items columns...");
  
  const result = await db.execute(sql`
    SELECT table_schema, column_name, data_type, is_nullable
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'question_bank_items'
    ORDER BY ordinal_position;
  `);

  console.log("\nColumns in question_bank_items:");
  console.table(result.rows);
}

checkColumns().catch((error) => {
  console.error("Check failed", error);
  process.exit(1);
});
