import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";

const tables = [
  "audit_logs",
  "notifications",
  "streaks",
  "study_sessions",
  "collaboration_messages",
  "collaboration_members",
  "collaboration_rooms",
  "accessibility_preferences",
  "learning_path_items",
  "learning_profiles",
  "user_badges",
  "badges",
  "quiz_answers",
  "quiz_attempts",
  "quiz_questions",
  "quizzes",
  "checklist_progress",
  "module_checklist_items",
  "assignments",
  "progress_tracking",
  "lesson_resources",
  "lesson_notes",
  "lessons",
  "user_module_selections",
  "module_access_codes",
  "modules",
  "subjects",
  "parent_student_links",
  "users",
  "roles",
];

const types = [
  "badge_rule",
  "collaboration_room_type",
  "learning_path_status",
  "learning_pace",
  "module_access_status",
  "assignment_status",
  "assignment_priority",
  "quiz_question_type",
  "quiz_difficulty",
  "resource_type",
  "lesson_type",
  "role",
  "role_name",
  "quiz_type",
  "difficulty",
];

async function reset() {
  for (const table of tables) {
    await db.execute(sql.raw(`DROP TABLE IF EXISTS ${table} CASCADE;`));
  }

  for (const type of types) {
    await db.execute(sql.raw(`DROP TYPE IF EXISTS ${type} CASCADE;`));
  }

  console.log("Database reset complete.");
}

reset().catch((error) => {
  console.error("Reset failed", error);
  process.exit(1);
});
