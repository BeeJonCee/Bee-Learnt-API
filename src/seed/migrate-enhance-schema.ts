import { db } from "../core/database/index.js";
import { sql } from "drizzle-orm";

/**
 * Migration script to enhance database schema
 * - Adds new enum values for question types
 * - Adds new columns to existing tables (subjects, modules, quiz_questions)
 * - Creates indexes for performance
 *
 * Run with: npx tsx src/seed/migrate-enhance-schema.ts
 */

export async function enhanceSchema() {
  console.log("🔄 Starting schema enhancements...\n");

  try {
    // ═══════════════════════════════════════════════════════
    // STEP 1: Extend quiz_question_type enum
    // ═══════════════════════════════════════════════════════
    console.log("📝 Step 1: Extending quiz_question_type enum...");

    const newQuestionTypes = [
      "multi_select",
      "true_false",
      "numeric",
      "matching",
      "ordering",
      "fill_in_blank",
    ];

    for (const type of newQuestionTypes) {
      try {
        await db.execute(sql`
          ALTER TYPE quiz_question_type ADD VALUE IF NOT EXISTS ${sql.raw(`'${type}'`)};
        `);
        console.log(`   ✓ Added enum value: ${type}`);
      } catch (error: any) {
        if (error.message?.includes("already exists")) {
          console.log(`   ⊙ Enum value already exists: ${type}`);
        } else {
          throw error;
        }
      }
    }

    // ═══════════════════════════════════════════════════════
    // STEP 2: Add columns to subjects table
    // ═══════════════════════════════════════════════════════
    console.log("\n📝 Step 2: Enhancing subjects table...");

    const subjectsColumns = [
      { name: "code", type: "VARCHAR(20)" },
      { name: "caps_document_url", type: "TEXT" },
      { name: "curriculum_id", type: "INTEGER REFERENCES curricula(id)" },
      { name: "icon_url", type: "TEXT" },
      { name: "color", type: "VARCHAR(7)" },
      { name: "is_active", type: "BOOLEAN DEFAULT TRUE NOT NULL" },
      { name: "deleted_at", type: "TIMESTAMPTZ" },
    ];

    for (const col of subjectsColumns) {
      try {
        await db.execute(sql.raw(`
          ALTER TABLE subjects ADD COLUMN IF NOT EXISTS ${col.name} ${col.type};
        `));
        console.log(`   ✓ Added column: subjects.${col.name}`);
      } catch (error: any) {
        if (error.message?.includes("already exists")) {
          console.log(`   ⊙ Column already exists: subjects.${col.name}`);
        } else {
          throw error;
        }
      }
    }

    // ═══════════════════════════════════════════════════════
    // STEP 3: Add columns to modules table
    // ═══════════════════════════════════════════════════════
    console.log("\n📝 Step 3: Enhancing modules table...");

    const modulesColumns = [
      { name: "term_number", type: "INTEGER" },
      { name: "topic_id", type: "INTEGER REFERENCES topics(id)" },
      { name: "estimated_minutes", type: "INTEGER" },
      { name: "prerequisite_module_id", type: "INTEGER" },
      { name: "is_active", type: "BOOLEAN DEFAULT TRUE NOT NULL" },
      { name: "deleted_at", type: "TIMESTAMPTZ" },
    ];

    for (const col of modulesColumns) {
      try {
        await db.execute(sql.raw(`
          ALTER TABLE modules ADD COLUMN IF NOT EXISTS ${col.name} ${col.type};
        `));
        console.log(`   ✓ Added column: modules.${col.name}`);
      } catch (error: any) {
        if (error.message?.includes("already exists")) {
          console.log(`   ⊙ Column already exists: modules.${col.name}`);
        } else {
          throw error;
        }
      }
    }

    // ═══════════════════════════════════════════════════════
    // STEP 4: Add columns to quiz_questions table
    // ═══════════════════════════════════════════════════════
    console.log("\n📝 Step 4: Enhancing quiz_questions table...");

    const quizQuestionsColumns = [
      { name: "difficulty", type: "quiz_difficulty DEFAULT 'medium'" },
      { name: "topic_id", type: "INTEGER REFERENCES topics(id)" },
      { name: "question_bank_item_id", type: "INTEGER REFERENCES question_bank_items(id)" },
      { name: "tags", type: "JSONB DEFAULT '[]'::jsonb" },
      { name: "image_url", type: "TEXT" },
      { name: "time_limit_seconds", type: "INTEGER" },
    ];

    for (const col of quizQuestionsColumns) {
      try {
        await db.execute(sql.raw(`
          ALTER TABLE quiz_questions ADD COLUMN IF NOT EXISTS ${col.name} ${col.type};
        `));
        console.log(`   ✓ Added column: quiz_questions.${col.name}`);
      } catch (error: any) {
        if (error.message?.includes("already exists")) {
          console.log(`   ⊙ Column already exists: quiz_questions.${col.name}`);
        } else {
          throw error;
        }
      }
    }

    // ═══════════════════════════════════════════════════════
    // STEP 5: Create indexes for performance
    // ═══════════════════════════════════════════════════════
    console.log("\n📝 Step 5: Creating performance indexes...");

    const indexes = [
      { name: "idx_subjects_curriculum", table: "subjects", column: "curriculum_id" },
      { name: "idx_subjects_active", table: "subjects", column: "is_active" },
      { name: "idx_modules_topic", table: "modules", column: "topic_id" },
      { name: "idx_modules_term", table: "modules", column: "term_number" },
      { name: "idx_modules_active", table: "modules", column: "is_active" },
      { name: "idx_quiz_questions_topic", table: "quiz_questions", column: "topic_id" },
      { name: "idx_quiz_questions_bank", table: "quiz_questions", column: "question_bank_item_id" },
      { name: "idx_quiz_questions_tags", table: "quiz_questions", column: "tags", type: "GIN" },
    ];

    for (const idx of indexes) {
      try {
        const indexType = idx.type || "BTREE";
        if (indexType === "GIN") {
          await db.execute(sql.raw(`
            CREATE INDEX IF NOT EXISTS ${idx.name} ON ${idx.table} USING GIN(${idx.column});
          `));
        } else {
          await db.execute(sql.raw(`
            CREATE INDEX IF NOT EXISTS ${idx.name} ON ${idx.table}(${idx.column});
          `));
        }
        console.log(`   ✓ Created index: ${idx.name} on ${idx.table}(${idx.column})`);
      } catch (error: any) {
        if (error.message?.includes("already exists")) {
          console.log(`   ⊙ Index already exists: ${idx.name}`);
        } else {
          throw error;
        }
      }
    }

    // ═══════════════════════════════════════════════════════
    // STEP 6: Create self-referencing FK constraint for modules
    // ═══════════════════════════════════════════════════════
    console.log("\n📝 Step 6: Adding self-referencing constraint to modules...");

    try {
      await db.execute(sql.raw(`
        ALTER TABLE modules
        ADD CONSTRAINT fk_modules_prerequisite
        FOREIGN KEY (prerequisite_module_id)
        REFERENCES modules(id)
        ON DELETE SET NULL;
      `));
      console.log("   ✓ Added FK constraint: modules.prerequisite_module_id → modules.id");
    } catch (error: any) {
      if (error.message?.includes("already exists")) {
        console.log("   ⊙ FK constraint already exists: fk_modules_prerequisite");
      } else {
        throw error;
      }
    }

    console.log("\n✅ Schema enhancements completed successfully!");
    console.log("\n📊 Summary:");
    console.log("   • Extended quiz_question_type enum with 6 new types");
    console.log("   • Added 7 columns to subjects table");
    console.log("   • Added 6 columns to modules table");
    console.log("   • Added 6 columns to quiz_questions table");
    console.log("   • Created 8 performance indexes");
    console.log("   • Added self-referencing FK constraint to modules");

  } catch (error) {
    console.error("\n❌ Error during schema enhancement:", error);
    throw error;
  }
}

// Auto-run when executed directly (e.g. `tsx src/seed/migrate-enhance-schema.ts`)
const isMain = process.argv[1]?.replace(/\\/g, "/").includes("seed/migrate-");
if (isMain) {
  enhanceSchema()
    .then(() => {
      console.log("\n✨ Migration complete!");
      process.exit(0);
    })
    .catch((error) => {
      console.error("\n💥 Migration failed:", error);
      process.exit(1);
    });
}
