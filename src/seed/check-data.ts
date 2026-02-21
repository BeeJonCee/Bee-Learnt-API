import "dotenv/config";
import { drizzle } from "drizzle-orm/neon-http";
import { neon } from "@neondatabase/serverless";
import * as schema from "../core/database/schema/index.js";

async function checkData() {
  const databaseUrl = process.env.DATABASE_URL;
  
  if (!databaseUrl) {
    console.error("❌ DATABASE_URL environment variable is not set!");
    process.exit(1);
  }

  const sql = neon(databaseUrl);
  const db = drizzle(sql, { schema });

  console.log("🔍 Checking data in key tables...\n");

  // Check users
  const usersResult = await sql`SELECT COUNT(*) as count FROM users`;
  console.log(`👥 Users: ${usersResult[0].count}`);

  // Check roles
  const rolesResult = await sql`SELECT COUNT(*) as count FROM roles`;
  console.log(`🎭 Roles: ${rolesResult[0].count}`);

  // Check subjects
  const subjectsResult = await sql`SELECT COUNT(*) as count FROM subjects`;
  console.log(`📚 Subjects: ${subjectsResult[0].count}`);

  // Check modules
  const modulesResult = await sql`SELECT COUNT(*) as count FROM modules`;
  console.log(`📦 Modules: ${modulesResult[0].count}`);

  // Check lessons
  const lessonsResult = await sql`SELECT COUNT(*) as count FROM lessons`;
  console.log(`📝 Lessons: ${lessonsResult[0].count}`);

  // Check assignments
  const assignmentsResult = await sql`SELECT COUNT(*) as count FROM assignments`;
  console.log(`📋 Assignments: ${assignmentsResult[0].count}`);

  // Check quizzes
  const quizzesResult = await sql`SELECT COUNT(*) as count FROM quizzes`;
  console.log(`❓ Quizzes: ${quizzesResult[0].count}`);

  // Check quiz questions
  const questionsResult = await sql`SELECT COUNT(*) as count FROM quiz_questions`;
  console.log(`❔ Quiz Questions: ${questionsResult[0].count}`);

  console.log("\n" + "=".repeat(50));

  // Get some sample data
  const subjects = await sql`SELECT id, name, min_grade, max_grade FROM subjects LIMIT 5`;
  if (subjects.length > 0) {
    console.log("\n📚 Sample Subjects:");
    subjects.forEach((s: any) => {
      console.log(`  - ${s.name} (Grades ${s.min_grade}-${s.max_grade})`);
    });
  }

  const modules = await sql`
    SELECT m.id, m.title, m.grade, s.name as subject_name 
    FROM modules m 
    JOIN subjects s ON m.subject_id = s.id 
    LIMIT 5
  `;
  if (modules.length > 0) {
    console.log("\n📦 Sample Modules:");
    modules.forEach((m: any) => {
      console.log(`  - Grade ${m.grade}: ${m.title} (${m.subject_name})`);
    });
  }

  const assignments = await sql`
    SELECT a.id, a.title, a.grade, s.name as subject_name
    FROM assignments a
    JOIN modules m ON a.module_id = m.id
    JOIN subjects s ON m.subject_id = s.id
    LIMIT 5
  `;
  if (assignments.length > 0) {
    console.log("\n📋 Sample Assignments:");
    assignments.forEach((a: any) => {
      console.log(`  - Grade ${a.grade}: ${a.title} (${a.subject_name})`);
    });
  }

  const quizzes = await sql`
    SELECT q.id, q.title, q.difficulty, s.name as subject_name
    FROM quizzes q
    JOIN modules m ON q.module_id = m.id
    JOIN subjects s ON m.subject_id = s.id
    LIMIT 5
  `;
  if (quizzes.length > 0) {
    console.log("\n❓ Sample Quizzes:");
    quizzes.forEach((q: any) => {
      console.log(`  - ${q.title} [${q.difficulty}] (${q.subject_name})`);
    });
  }

  // Check if there are any user module selections
  const userModuleSelections = await sql`SELECT COUNT(*) as count FROM user_module_selections`;
  console.log(`\n🔐 User Module Selections: ${userModuleSelections[0].count}`);

  if (parseInt(userModuleSelections[0].count) === 0) {
    console.log("\n⚠️  Warning: No user module selections found!");
    console.log("   Users need to select modules before they can see them.");
  }

  console.log("\n✅ Data check complete!");
}

checkData().catch((error) => {
  console.error("❌ Error checking data:", error);
  process.exit(1);
});
