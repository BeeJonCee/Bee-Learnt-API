import "dotenv/config";
import { drizzle } from "drizzle-orm/neon-http";
import { neon } from "@neondatabase/serverless";
import * as schema from "../core/database/schema/index.js";

async function checkTables() {
  const databaseUrl = process.env.DATABASE_URL;
  
  if (!databaseUrl) {
    console.error("❌ DATABASE_URL environment variable is not set!");
    process.exit(1);
  }

  const sql = neon(databaseUrl);
  const db = drizzle(sql, { schema });

  console.log("🔍 Checking tables in Neon database...\n");

  // Get all tables from the schema
  const schemaTableNames = Object.keys(schema)
    .filter((key) => !key.includes("Enum"))
    .sort();

  console.log("📋 Expected tables from schema:");
  console.log("================================");
  schemaTableNames.forEach((table, index) => {
    console.log(`${index + 1}. ${table}`);
  });
  console.log(`\nTotal expected tables: ${schemaTableNames.length}\n`);

  // Query actual tables in the database
  const result = await sql`
    SELECT table_name 
    FROM information_schema.tables 
    WHERE table_schema = 'public' 
      AND table_type = 'BASE TABLE'
    ORDER BY table_name;
  `;

  console.log("✅ Actual tables in database:");
  console.log("==============================");
  result.forEach((row: any, index: number) => {
    console.log(`${index + 1}. ${row.table_name}`);
  });
  console.log(`\nTotal tables in database: ${result.length}\n`);

  // Check for any missing tables
  const dbTableNames = result.map((row: any) => row.table_name);
  const missingTables = schemaTableNames.filter(
    (table) => !dbTableNames.includes(table)
  );

  if (missingTables.length > 0) {
    console.log("⚠️  Missing tables:");
    console.log("===================");
    missingTables.forEach((table, index) => {
      console.log(`${index + 1}. ${table}`);
    });
  } else {
    console.log("✨ All expected tables are present!");
  }

  // Check for extra tables (not in schema but in database)
  const extraTables = dbTableNames.filter(
    (table: string) => !schemaTableNames.includes(table)
  );

  if (extraTables.length > 0) {
    console.log("\n📌 Extra tables in database (not in schema):");
    console.log("===========================================");
    extraTables.forEach((table: string, index: number) => {
      console.log(`${index + 1}. ${table}`);
    });
  }

  console.log("\n✅ Check complete!");
}

checkTables().catch((error) => {
  console.error("❌ Error checking tables:", error);
  process.exit(1);
});
