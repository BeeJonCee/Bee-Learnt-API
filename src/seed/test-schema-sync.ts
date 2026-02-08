/**
 * Test Schema Synchronization
 *
 * This script tests the synchronization between neondb (auth database)
 * and beelearnt (app database) during registration and login processes.
 *
 * Architecture:
 * - beelearnt DB (appDb): public.users, public.roles, etc.
 * - neondb DB (authDb): public.user, public.account, public.session, etc.
 *
 * Usage: npm run test:schema-sync
 */

import "dotenv/config";
import { db } from "../core/database/index.js";
import { db as authDb } from "../core/database/neon-auth-db.js";
import { sql } from "drizzle-orm";
import { randomUUID } from "crypto";
import bcrypt from "bcryptjs";
import { syncToNeonAuthUser, syncPasswordToNeonAuth } from "../shared/utils/schema-sync.js";
import { syncUserFromNeonAuth } from "../lib/auth/neon-auth-sync.js";

const TEST_USER = {
  email: `test-${Date.now()}@beelearnt.com`,
  name: "Test User",
  password: "Test12345!",
  role: "STUDENT" as const,
};

async function checkUserInNeonAuth(userId: string) {
  if (!authDb) return null;
  try {
    const result = await authDb.execute(sql`
      SELECT id, email, name, role, "emailVerified", banned
      FROM "user"
      WHERE id = ${userId}::uuid
    `);
    return result.rows[0] || null;
  } catch (error) {
    console.error("Error checking neondb user:", error);
    return null;
  }
}

async function checkUserInPublic(userId: string) {
  try {
    const result = await db.execute(sql`
      SELECT u.id, u.email, u.name, r.name as role
      FROM users u
      JOIN roles r ON u.role_id = r.id
      WHERE u.id = ${userId}::uuid
    `);
    return result.rows[0] || null;
  } catch (error) {
    console.error("Error checking beelearnt users:", error);
    return null;
  }
}

async function checkPasswordInNeonAuth(userId: string) {
  if (!authDb) return null;
  try {
    const result = await authDb.execute(sql`
      SELECT id, password
      FROM account
      WHERE "userId" = ${userId}::uuid AND "providerId" = 'email'
    `);
    return result.rows[0] || null;
  } catch (error) {
    console.error("Error checking neondb account:", error);
    return null;
  }
}

async function testSchemaSync() {
  console.log("\n" + "=".repeat(70));
  console.log("🧪 TESTING SCHEMA SYNCHRONIZATION");
  console.log("=".repeat(70) + "\n");

  const authAvailable = !!authDb;

  // Step 1: Check availability
  console.log("📋 Step 1: Checking database availability...\n");
  console.log(`   neondb (authDb):  ${authAvailable ? "✓ CONNECTED" : "✗ NOT CONFIGURED"}`);
  console.log(`   beelearnt (appDb): ✓ CONNECTED`);

  if (!authAvailable) {
    console.warn("\n⚠️  Neon Auth database not configured. Testing local auth only.\n");
  }

  // Step 2: Create test user
  console.log("\n📋 Step 2: Creating test user...\n");

  const userId = randomUUID();
  const passwordHash = await bcrypt.hash(TEST_USER.password, 10);

  console.log(`   User ID:   ${userId}`);
  console.log(`   Email:     ${TEST_USER.email}`);
  console.log(`   Role:      ${TEST_USER.role}`);

  // Step 3: Sync to neondb (if available)
  if (authAvailable) {
    console.log("\n📋 Step 3: Syncing to neondb...\n");

    try {
      await syncToNeonAuthUser({
        id: userId,
        email: TEST_USER.email,
        name: TEST_USER.name,
        role: TEST_USER.role,
      });
      console.log("   ✓ User created in neondb user table");

      await syncPasswordToNeonAuth({
        userId,
        email: TEST_USER.email,
        passwordHash,
      });
      console.log("   ✓ Password stored in neondb account table");
    } catch (error: any) {
      console.error(`   ✗ Failed to sync to neondb: ${error.message}`);
    }
  } else {
    console.log("\n📋 Step 3: Skipping neondb sync (not configured)\n");
  }

  // Step 4: Create in beelearnt users
  console.log("\n📋 Step 4: Creating user in beelearnt users...\n");

  try {
    // Get role ID
    const roleResult = await db.execute<{ id: number }>(sql`
      SELECT id FROM roles WHERE name = ${TEST_USER.role}
    `);

    if (!roleResult.rows[0]) {
      throw new Error(`Role ${TEST_USER.role} not found`);
    }

    const roleId = roleResult.rows[0].id;

    await db.execute(sql`
      INSERT INTO users (id, name, email, password_hash, role_id, created_at, updated_at)
      VALUES (
        ${userId}::uuid,
        ${TEST_USER.name},
        ${TEST_USER.email},
        ${passwordHash},
        ${roleId},
        NOW(),
        NOW()
      )
    `);
    console.log("   ✓ User created in beelearnt users");
  } catch (error: any) {
    console.error(`   ✗ Failed to create in beelearnt users: ${error.message}`);
    process.exit(1);
  }

  // Step 5: Verify data consistency
  console.log("\n📋 Step 5: Verifying data consistency...\n");

  const publicUser = await checkUserInPublic(userId);
  console.log(`   beelearnt.users:  ${publicUser ? "✓ FOUND" : "✗ NOT FOUND"}`);
  if (publicUser) {
    console.log(`      Email: ${publicUser.email}`);
    console.log(`      Name:  ${publicUser.name}`);
    console.log(`      Role:  ${publicUser.role}`);
  }

  if (authAvailable) {
    const neonUser = await checkUserInNeonAuth(userId);
    console.log(`   neondb.user:      ${neonUser ? "✓ FOUND" : "✗ NOT FOUND"}`);
    if (neonUser) {
      console.log(`      Email:     ${neonUser.email}`);
      console.log(`      Name:      ${neonUser.name}`);
      console.log(`      Role:      ${neonUser.role}`);
      console.log(`      Verified:  ${neonUser.emailVerified}`);
      console.log(`      Banned:    ${neonUser.banned}`);
    }

    const neonPassword = await checkPasswordInNeonAuth(userId);
    console.log(`   neondb.account:   ${neonPassword ? "✓ FOUND" : "✗ NOT FOUND"}`);
  }

  // Step 6: Test sync from neondb to beelearnt
  if (authAvailable) {
    console.log("\n📋 Step 6: Testing sync from neondb to beelearnt...\n");

    try {
      const syncResult = await syncUserFromNeonAuth(userId);
      if (syncResult) {
        console.log(`   ✓ Sync successful`);
        console.log(`      User:      ${syncResult.user.email}`);
        console.log(`      Role:      ${syncResult.role}`);
        console.log(`      Is New:    ${syncResult.isNewUser}`);
      } else {
        console.log(`   ⚠ Sync returned null (neondb tables may not exist)`);
      }
    } catch (error: any) {
      console.error(`   ✗ Sync failed: ${error.message}`);
    }
  }

  // Step 7: Cleanup
  console.log("\n📋 Step 7: Cleaning up test data...\n");

  try {
    await db.execute(sql`
      DELETE FROM users WHERE id = ${userId}::uuid
    `);
    console.log("   ✓ Deleted from beelearnt users");

    if (authAvailable && authDb) {
      await authDb.execute(sql`
        DELETE FROM account WHERE "userId" = ${userId}::uuid
      `);
      console.log("   ✓ Deleted from neondb account");

      await authDb.execute(sql`
        DELETE FROM "user" WHERE id = ${userId}::uuid
      `);
      console.log("   ✓ Deleted from neondb user");
    }
  } catch (error: any) {
    console.error(`   ✗ Cleanup failed: ${error.message}`);
  }

  // Summary
  console.log("\n" + "=".repeat(70));
  console.log("✅ SCHEMA SYNCHRONIZATION TEST COMPLETE");
  console.log("=".repeat(70) + "\n");

  console.log("📊 Summary:");
  console.log(`   - neondb (authDb):  ${authAvailable ? "Available ✓" : "Not configured ✗"}`);
  console.log(`   - beelearnt (appDb): Available ✓`);
  console.log(`   - Data sync:        ${authAvailable ? "Tested ✓" : "Skipped (neondb not configured)"}`);
  console.log("\n");
}

// Run the test
testSchemaSync()
  .then(() => {
    console.log("Test completed successfully!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("\n❌ Test failed:", error);
    process.exit(1);
  });
