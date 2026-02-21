import "dotenv/config";
import { db } from "../core/database/index.js";
import { modules, users, userModuleSelections } from "../core/database/schema/index.js";
import { eq, and } from "drizzle-orm";

async function unlockAllModules() {
  console.log("🔓 Unlocking all modules for test user...\n");

  // Get the test user
  const [testUser] = await db
    .select()
    .from(users)
    .where(eq(users.email, "student@test.com"));

  if (!testUser) {
    console.error("❌ Test user not found. Please run create-test-user.ts first.");
    process.exit(1);
  }

  console.log(`👤 User: ${testUser.name} (${testUser.email})`);

  // Get all modules
  const allModules = await db.select().from(modules);
  console.log(`\n📦 Found ${allModules.length} modules to unlock...\n`);

  let unlocked = 0;
  let alreadyUnlocked = 0;

  for (const module of allModules) {
    // Check if already selected
    const [existing] = await db
      .select()
      .from(userModuleSelections)
      .where(
        and(
          eq(userModuleSelections.userId, testUser.id),
          eq(userModuleSelections.moduleId, module.id)
        )
      );

    if (existing) {
      if (existing.status === "unlocked") {
        alreadyUnlocked++;
        console.log(`  ✓ Already unlocked: ${module.title}`);
      } else {
        await db
          .update(userModuleSelections)
          .set({ status: "unlocked", unlockedAt: new Date() })
          .where(eq(userModuleSelections.id, existing.id));
        unlocked++;
        console.log(`  🔓 Unlocked: ${module.title}`);
      }
    } else {
      await db.insert(userModuleSelections).values({
        userId: testUser.id,
        moduleId: module.id,
        status: "unlocked",
        unlockedAt: new Date(),
      });
      unlocked++;
      console.log(`  🔓 Unlocked: ${module.title}`);
    }
  }

  console.log(`\n✅ Summary:`);
  console.log(`   Newly unlocked: ${unlocked}`);
  console.log(`   Already unlocked: ${alreadyUnlocked}`);
  console.log(`   Total modules: ${allModules.length}`);
  console.log(`\n💡 Now login with student@test.com / password123`);
  console.log(`   You should see all modules, lessons, assignments, and quizzes!`);
}

unlockAllModules()
  .then(() => {
    console.log("\n✅ Complete!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("❌ Error unlocking modules:", error);
    process.exit(1);
  });
