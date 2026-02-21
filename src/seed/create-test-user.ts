import "dotenv/config";
import { hash } from "bcryptjs";
import { randomUUID } from "crypto";
import { db } from "../core/database/index.js";
import { neonUsers, roles, users } from "../core/database/schema/index.js";
import { eq } from "drizzle-orm";

async function createTestUser() {
  console.log("🔐 Creating test user...\n");

  // Get the STUDENT role
  const [studentRole] = await db
    .select()
    .from(roles)
    .where(eq(roles.name, "STUDENT"));

  if (!studentRole) {
    console.error("❌ STUDENT role not found. Please run the seed script first.");
    process.exit(1);
  }

  // Check if user already exists
  const [existingUser] = await db
    .select()
    .from(users)
    .where(eq(users.email, "student@test.com"));

  if (existingUser) {
    console.log("✅ Test user already exists:");
    console.log("   Email: student@test.com");
    console.log("   Password: password123");
    return;
  }

  const [existingNeon] = await db
    .select({ id: neonUsers.id })
    .from(neonUsers)
    .where(eq(neonUsers.email, "student@test.com"));

  const userId = existingNeon?.id ?? randomUUID();

  if (!existingNeon) {
    await db.insert(neonUsers).values({
      id: userId,
      email: "student@test.com",
      name: "Test Student",
      role: "STUDENT",
      emailVerified: false,
      banned: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  }

  // Create test user
  const passwordHash = await hash("password123", 10);
  
  const [newUser] = await db
    .insert(users)
    .values({
      id: userId,
      name: "Test Student",
      email: "student@test.com",
      passwordHash,
      roleId: studentRole.id,
      image: null,
    })
    .returning();

  console.log("✅ Test user created successfully!");
  console.log("\n📧 Login credentials:");
  console.log("   Email: student@test.com");
  console.log("   Password: password123");
  console.log("\n💡 Use these credentials to login to your app.");
  console.log("\n⚠️  Note: After logging in, you'll need to select modules");
  console.log("   from the available subjects to see content.");
}

createTestUser()
  .then(() => {
    console.log("\n✅ Complete!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("❌ Error creating test user:", error);
    process.exit(1);
  });
