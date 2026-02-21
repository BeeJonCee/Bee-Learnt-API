import "dotenv/config";
import { hash } from "bcryptjs";
import { randomUUID } from "crypto";
import { db } from "../core/database/index.js";
import { neonUsers, roles, users, modules, userModuleSelections } from "../core/database/schema/index.js";
import { eq } from "drizzle-orm";

async function createAndSetupUser() {
  const email = "j.chauke@outlook.com";
  const password = process.argv[2];

  if (!password) {
    console.error("❌ Please provide a password as an argument");
    console.log("\nUsage: npx tsx src/seed/create-user.ts <password>");
    process.exit(1);
  }

  console.log(`🔐 Creating user: ${email}\n`);

  // Check if user already exists
  const [existingUser] = await db
    .select()
    .from(users)
    .where(eq(users.email, email));

  if (existingUser) {
    console.log("⚠️  User already exists!");
    console.log(`   Name: ${existingUser.name}`);
    console.log(`   Email: ${existingUser.email}`);
    console.log("\n💡 If you want to reset the password, use a different script.");
    process.exit(0);
  }

  // Get the STUDENT role
  const [studentRole] = await db
    .select()
    .from(roles)
    .where(eq(roles.name, "STUDENT"));

  if (!studentRole) {
    console.error("❌ STUDENT role not found. Please run the seed script first.");
    process.exit(1);
  }

  const [existingNeon] = await db
    .select({ id: neonUsers.id })
    .from(neonUsers)
    .where(eq(neonUsers.email, email));

  const userId = existingNeon?.id ?? randomUUID();

  if (!existingNeon) {
    await db.insert(neonUsers).values({
      id: userId,
      email,
      name: "J. Chauke",
      role: "STUDENT",
      emailVerified: false,
      banned: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  }

  // Create user
  const passwordHash = await hash(password, 10);
  
  const [newUser] = await db
    .insert(users)
    .values({
      id: userId,
      name: "J. Chauke",
      email: email,
      passwordHash,
      roleId: studentRole.id,
      image: null,
    })
    .returning();

  console.log("✅ User created successfully!");
  console.log(`   Name: ${newUser.name}`);
  console.log(`   Email: ${newUser.email}`);

  // Unlock all modules
  console.log(`\n🔓 Unlocking all modules...\n`);
  const allModules = await db.select().from(modules);
  
  for (const module of allModules) {
    await db.insert(userModuleSelections).values({
      userId: newUser.id,
      moduleId: module.id,
      status: "unlocked",
      unlockedAt: new Date(),
    });
    console.log(`  ✓ ${module.title}`);
  }

  console.log(`\n✅ Setup complete!`);
  console.log(`   Unlocked ${allModules.length} modules`);
  console.log(`\n📧 Login credentials:`);
  console.log(`   Email: ${email}`);
  console.log(`   Password: ${password}`);
  console.log(`\n💡 You can now login and access all content!`);
}

createAndSetupUser()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error("❌ Error:", error);
    process.exit(1);
  });
