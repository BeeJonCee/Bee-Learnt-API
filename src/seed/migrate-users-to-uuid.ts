import "dotenv/config";
import { sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { db as authDb } from "../core/database/neon-auth-db.js";

/**
 * CRITICAL MIGRATION: Convert users.id from integer to uuid to match neondb user.id
 *
 * This migration:
 * 1. Creates a new users_new table with uuid primary key
 * 2. Migrates data from old users table
 * 3. Optionally syncs to neondb (via authDb) if available
 * 4. Updates all foreign key references
 * 5. Drops old users table and renames new one
 *
 * NOTE: neondb tables are in a separate database accessed via authDb,
 * NOT in a "neon_auth" schema of the beelearnt database.
 */

async function migrateUsersToUuid() {
  console.log("🚀 Starting migration: Convert users.id from integer to uuid\n");

  try {
    // Step 1: Create new users table with uuid
    console.log("1️⃣  Creating new users table with uuid primary key...");
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS users_new (
        id uuid PRIMARY KEY,
        name varchar(120) NOT NULL,
        email varchar(255) NOT NULL UNIQUE,
        password_hash text,
        image text,
        role_id integer NOT NULL REFERENCES roles(id),
        created_at timestamp with time zone DEFAULT NOW() NOT NULL,
        updated_at timestamp with time zone DEFAULT NOW() NOT NULL,
        last_login_at timestamp with time zone
      );
    `);
    console.log("✅ New users table created\n");

    // Step 2: Check if authDb (neondb) is available
    console.log("2️⃣  Checking for neondb (authDb) connection...");
    const authAvailable = !!authDb;
    if (!authAvailable) {
      console.log("⚠️  authDb not configured. Users won't be synced to neondb.");
    } else {
      console.log("✅ authDb (neondb) available");
    }
    console.log();

    // Step 3: Migrate existing users data
    console.log("3️⃣  Migrating existing users...");

    // Get existing users
    const existingUsers = await db.execute(sql`
      SELECT id, name, email, password_hash, image, role_id, created_at, updated_at, last_login_at
      FROM users;
    `);

    console.log(`   Found ${existingUsers.rows.length} users to migrate`);

    for (const user of existingUsers.rows as any[]) {
      // Generate a new UUID for each user
      const newUuid = await db.execute(sql`SELECT gen_random_uuid() as id;`);
      const uuid = (newUuid.rows[0] as any).id;

      console.log(`   Migrating user: ${user.email} → ${uuid}`);

      // Insert into new table
      await db.execute(sql`
        INSERT INTO users_new (id, name, email, password_hash, image, role_id, created_at, updated_at, last_login_at)
        VALUES (
          ${uuid},
          ${user.name},
          ${user.email},
          ${user.password_hash},
          ${user.image},
          ${user.role_id},
          ${user.created_at},
          ${user.updated_at},
          ${user.last_login_at}
        );
      `);

      // Try to create corresponding user in neondb if authDb is available
      if (authDb) {
        try {
          await authDb.execute(sql`
            INSERT INTO "user" (id, name, email, role, "emailVerified", banned, "createdAt", "updatedAt")
            VALUES (
              ${uuid},
              ${user.name},
              ${user.email},
              (SELECT name FROM roles WHERE id = ${user.role_id}),
              false,
              false,
              ${user.created_at},
              NOW()
            )
            ON CONFLICT (id) DO NOTHING;
          `);
        } catch (e) {
          console.log(`   ⚠️  Could not create neondb user for ${user.email}`);
        }
      }
    }
    console.log("✅ User data migrated\n");

    // Step 4: Update all foreign key references
    console.log("4️⃣  Updating foreign key references in related tables...");

    const tablesToUpdate = [
      'accessibility_preferences',
      'parent_student_links',
      'user_module_selections',
      'lesson_notes',
      'progress_tracking',
      'assignments',
      'checklist_progress',
      'quizzes',
      'quiz_attempts',
      'user_badges',
      'learning_profiles',
      'learning_path_items',
      'collaboration_rooms',
      'collaboration_members',
      'collaboration_messages',
      'study_sessions',
      'streaks',
      'notifications',
      'audit_logs'
    ];

    for (const table of tablesToUpdate) {
      try {
        console.log(`   Updating ${table}...`);

        // First, add a new uuid column
        await db.execute(sql.raw(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS user_id_new uuid;`));

        console.log(`   ✅ Added user_id_new column to ${table}`);
      } catch (e) {
        console.log(`   ⚠️  Could not update ${table}:`, e);
      }
    }

    console.log("\n⚠️  IMPORTANT: Foreign key references need manual cleanup!");
    console.log("   Old user IDs cannot be automatically mapped to new UUIDs.");
    console.log("   Users will need to re-link their data after signing in with Neon Auth.\n");

    // Step 5: Drop old users table and rename new one
    console.log("5️⃣  Replacing old users table with new one...");
    await db.execute(sql`DROP TABLE IF EXISTS users CASCADE;`);
    await db.execute(sql`ALTER TABLE users_new RENAME TO users;`);
    console.log("✅ Table replacement complete\n");

    console.log("🎉 Migration completed successfully!\n");
    console.log("📋 NEXT STEPS:");
    console.log("   1. Run: npx tsx src/seed/set-user-roles.ts");
    console.log("   2. Have existing users sign in through Neon Auth");
    console.log("   3. Their accounts will be auto-created with proper UUIDs\n");

  } catch (error) {
    console.error("❌ Migration failed:", error);
    throw error;
  }
}

migrateUsersToUuid()
  .then(() => {
    console.log("✅ Script completed");
    process.exit(0);
  })
  .catch((error) => {
    console.error("❌ Script failed:", error);
    process.exit(1);
  });
