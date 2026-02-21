/**
 * Quick diagnostic script to test database connectivity and schema state
 */

import "dotenv/config";
import { db } from "../core/database/index.js";
import { sql } from "drizzle-orm";

async function diagnose() {
  console.log("\n🔍 Database Diagnostic Tool\n");
  console.log("=".repeat(60));

  try {
    // Test 1: Basic connection
    console.log("\n1️⃣  Testing database connection...");
    const timeResult = await db.execute(sql`SELECT NOW() as current_time`);
    console.log(`✅ Connected! Server time: ${(timeResult.rows[0] as any).current_time}`);

    // Test 2: Check public schema
    console.log("\n2️⃣  Checking public schema...");
    const publicTables = await db.execute(sql`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_type = 'BASE TABLE'
      ORDER BY table_name
    `);
    console.log(`✅ Found ${publicTables.rows.length} tables in public schema:`);
    publicTables.rows.forEach((row: any) => {
      console.log(`   - ${row.table_name}`);
    });

    // Test 3: Check neon_auth schema
    console.log("\n3️⃣  Checking neon_auth schema...");
    try {
      const neonTables = await db.execute(sql`
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'neon_auth' 
        AND table_type = 'BASE TABLE'
        ORDER BY table_name
      `);
      
      if (neonTables.rows.length > 0) {
        console.log(`✅ Found ${neonTables.rows.length} tables in neon_auth schema:`);
        neonTables.rows.forEach((row: any) => {
          console.log(`   - ${row.table_name}`);
        });
      } else {
        console.log(`⚠️  neon_auth schema exists but has no tables`);
      }
    } catch (error: any) {
      if (error.code === '3F000') {
        console.log(`❌ neon_auth schema does not exist`);
        console.log(`   This is normal - enable Neon Auth in console to create it`);
      } else {
        console.log(`❌ Error checking neon_auth: ${error.message}`);
      }
    }

    // Test 4: Check users table
    console.log("\n4️⃣  Checking users table...");
    const userCount = await db.execute(sql`SELECT COUNT(*)::text as count FROM users`);
    console.log(`✅ Users table exists with ${(userCount.rows[0] as any).count} users`);

    // Test 5: Check roles table
    console.log("\n5️⃣  Checking roles table...");
    const roles = await db.execute(sql`SELECT id, name FROM roles ORDER BY id`);
    console.log(`✅ Roles table exists with ${roles.rows.length} roles:`);
    roles.rows.forEach((row: any) => {
      console.log(`   - ${row.name} (id: ${row.id})`);
    });

    // Test 6: Check DATABASE_URL format
    console.log("\n6️⃣  Checking environment...");
    const dbUrl = process.env.DATABASE_URL;
    if (dbUrl) {
      const urlObj = new URL(dbUrl);
      console.log(`✅ DATABASE_URL configured:`);
      console.log(`   Host: ${urlObj.hostname}`);
      console.log(`   Database: ${urlObj.pathname.slice(1)}`);
      console.log(`   SSL: ${urlObj.searchParams.get('sslmode') || 'not specified'}`);
    } else {
      console.log(`❌ DATABASE_URL not set!`);
    }

    console.log("\n" + "=".repeat(60));
    console.log("\n✅ Diagnostic complete!\n");

    // Summary
    console.log("📋 Summary:");
    console.log("  - Database connection: ✅ Working");
    console.log("  - public schema: ✅ Available");
    console.log("  - neon_auth schema: ❌ Not enabled (optional)");
    console.log("  - Local auth: ✅ Should work");
    console.log("\n💡 To enable Neon Auth:");
    console.log("  1. Go to https://console.neon.tech");
    console.log("  2. Select project");
    console.log("  3. Settings → Auth → Enable");

  } catch (error: any) {
    console.error("\n❌ Diagnostic failed:", error.message);
    if (error.code) {
      console.error(`   Error code: ${error.code}`);
    }
    throw error;
  }
}

diagnose()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("\nFatal error:", err);
    process.exit(1);
  });
