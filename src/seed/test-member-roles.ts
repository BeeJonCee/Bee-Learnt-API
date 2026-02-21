/**
 * Test script to check neondb member table structure and role mappings
 *
 * This script:
 * 1. Connects to the neondb database (via authDb)
 * 2. Inspects member table structure and data
 * 3. Tests role mapping logic
 * 4. Displays current member-to-role assignments
 *
 * NOTE: Neon Auth tables live in the public schema of a separate "neondb"
 * database, NOT in a "neon_auth" schema of the app database.
 */

import "dotenv/config";
import { sql } from "drizzle-orm";
import { db as authDb } from "../core/database/neon-auth-db.js";
import { mapMemberRoleToBeeRole } from "../services/neon-member.service.js";

interface MemberRecord extends Record<string, unknown> {
  id: string;
  organizationId: string;
  userId: string;
  role: string;
  createdAt: Date;
}

interface UserInfo extends Record<string, unknown> {
  userId: string;
  email: string;
  name: string | null;
  userRole: string | null;
}

async function main() {
  console.log("\n🔍 Testing neondb member table and role mappings\n");
  console.log("=".repeat(80));

  if (!authDb) {
    console.log("\n❌ NEON_AUTH_DATABASE_URL not set. Cannot inspect neondb.");
    process.exit(1);
  }

  try {
    // 1. Check member table structure
    console.log("\n1️⃣ Inspecting member table structure...");
    const tableCheck = await authDb.execute(
      sql`SELECT table_name FROM information_schema.tables
          WHERE table_schema = 'public' AND table_name = 'member'`
    );

    if (tableCheck.rows.length === 0) {
      console.log("❌ member table doesn't exist in neondb");
      return;
    }

    const columns = await authDb.execute<{ column_name: string; data_type: string }>(
      sql`SELECT column_name, data_type
          FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = 'member'
          ORDER BY ordinal_position`
    );

    console.log("✅ member table structure:");
    console.table(columns.rows);

    // 2. Get member count
    console.log("\n2️⃣ Checking member records...");
    const countResult = await authDb.execute<{ count: string }>(
      sql`SELECT COUNT(*)::text as count FROM member`
    );
    const memberCount = Number.parseInt(countResult.rows[0]?.count || "0");
    console.log(`📊 Total members: ${memberCount}`);

    if (memberCount === 0) {
      console.log("\n⚠️  No members found. Create test members via:");
      console.log("   - Register new users with organizations");
      console.log("   - Use Neon Console to add members manually");
      return;
    }

    // 3. Get all members with details
    console.log("\n3️⃣ Fetching member details...");
    const members = await authDb.execute<MemberRecord>(
      sql`SELECT
            m.id,
            m."organizationId",
            m."userId",
            m.role,
            m."createdAt"
          FROM member m
          ORDER BY m."createdAt" DESC
          LIMIT 20`
    );

    console.log(`\n📋 Members (showing up to 20):`);
    console.table(members.rows);

    // 4. Get user information for members
    console.log("\n4️⃣ Fetching user information...");
    const usersInfo = await authDb.execute<UserInfo>(
      sql`SELECT
            u.id as "userId",
            u.email,
            u.name,
            u.role as "userRole"
          FROM "user" u
          WHERE u.id IN (SELECT "userId" FROM member)
          ORDER BY u.email`
    );

    console.log("\n👥 User details:");
    console.table(usersInfo.rows);

    // 5. Test role mappings
    console.log("\n5️⃣ Testing role mappings...");
    console.log("=".repeat(80));

    const testRoles = [
      "owner",
      "admin",
      "parent",
      "guardian",
      "member",
      "student",
      "OWNER",
      "PARENT",
      "STUDENT",
      "custom_role",
    ];

    console.log("\n📊 Member Role → BeeLearnt Role Mappings:");
    console.log("-".repeat(50));
    for (const role of testRoles) {
      const mapped = mapMemberRoleToBeeRole(role);
      const emoji = mapped === "ADMIN" ? "👑" : mapped === "PARENT" ? "👨‍👩‍👧" : "🎓";
      console.log(`${emoji} ${role.padEnd(15)} → ${mapped}`);
    }

    // 6. Show actual member-to-role assignments
    if (members.rows.length > 0) {
      console.log("\n6️⃣ Current member-to-role assignments:");
      console.log("=".repeat(80));

      for (const member of members.rows) {
        const userInfo = usersInfo.rows.find(u => u.userId === member.userId);
        const mappedRole = mapMemberRoleToBeeRole(member.role);

        console.log(`\n👤 User: ${userInfo?.email || member.userId}`);
        console.log(`   Name: ${userInfo?.name || "N/A"}`);
        console.log(`   Member Role: ${member.role}`);
        console.log(`   Mapped to: ${mappedRole}`);
        console.log(`   User Table Role: ${userInfo?.userRole || "Not set"}`);
        console.log(`   Organization: ${member.organizationId}`);

        if (userInfo?.userRole !== mappedRole) {
          console.log(`   ⚠️  Role mismatch! user.role should be updated to ${mappedRole}`);
        } else {
          console.log(`   ✅ Roles in sync`);
        }
      }
    }

    // 7. Check for role mismatches
    console.log("\n7️⃣ Checking for role mismatches...");
    const mismatches = await authDb.execute(
      sql`SELECT
            u.email,
            u.role as user_role,
            m.role as member_role,
            m."organizationId"
          FROM "user" u
          JOIN member m ON u.id = m."userId"
          WHERE u.role IS NOT NULL`
    );

    if (mismatches.rows.length > 0) {
      console.log("\n📊 User role vs Member role comparison:");
      console.table(mismatches.rows);
    }

    // 8. Show organizations
    console.log("\n8️⃣ Organizations:");
    const orgs = await authDb.execute(
      sql`SELECT
            o.id,
            o.name,
            o.slug,
            o."createdAt",
            COUNT(m.id)::text as member_count
          FROM organization o
          LEFT JOIN member m ON o.id = m."organizationId"
          GROUP BY o.id, o.name, o.slug, o."createdAt"
          ORDER BY o."createdAt" DESC`
    );

    if (orgs.rows.length > 0) {
      console.log("\n🏢 Organizations:");
      console.table(orgs.rows);
    } else {
      console.log("\n⚠️  No organizations found");
    }

    console.log("\n" + "=".repeat(80));
    console.log("✅ Member role check complete!");
    console.log("\n💡 Key Points:");
    console.log("   • Member roles (owner/admin) → ADMIN");
    console.log("   • Member roles (parent/guardian) → PARENT");
    console.log("   • Member roles (member/student/other) → STUDENT");
    console.log("   • Organization context determines effective role");
    console.log("   • Auth middleware uses member role when organizationId is present");

  } catch (error) {
    console.error("\n❌ Error:", error);
    throw error;
  }
}

main()
  .then(() => {
    console.log("\n👋 Done!");
    process.exit(0);
  })
  .catch((err) => {
    console.error("Failed:", err);
    process.exit(1);
  });
