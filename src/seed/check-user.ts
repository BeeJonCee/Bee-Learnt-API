import "dotenv/config";
import { db } from "../core/database/index.js";
import { users, roles, userModuleSelections, modules } from "../core/database/schema/index.js";
import { eq } from "drizzle-orm";

async function checkUser() {
  const email = "j.chauke@outlook.com";
  
  console.log(`🔍 Checking user: ${email}\n`);

  const [user] = await db
    .select({
      id: users.id,
      name: users.name,
      email: users.email,
      roleId: users.roleId,
      createdAt: users.createdAt,
      passwordHash: users.passwordHash,
    })
    .from(users)
    .where(eq(users.email, email));

  if (!user) {
    console.log("❌ User not found in database");
    console.log("\n💡 Would you like to:");
    console.log("   1. Create this user account");
    console.log("   2. Register through the app");
    return;
  }

  console.log("✅ User found!");
  console.log(`   Name: ${user.name}`);
  console.log(`   Email: ${user.email}`);
  console.log(`   Created: ${user.createdAt}`);
  console.log(`   Has password: ${user.passwordHash ? "Yes" : "No"}`);

  // Get role
  const [role] = await db
    .select()
    .from(roles)
    .where(eq(roles.id, user.roleId));

  console.log(`   Role: ${role?.name || "Unknown"}`);

  // Check module selections
  const selections = await db
    .select({
      moduleId: userModuleSelections.moduleId,
      status: userModuleSelections.status,
      moduleTitle: modules.title,
    })
    .from(userModuleSelections)
    .innerJoin(modules, eq(userModuleSelections.moduleId, modules.id))
    .where(eq(userModuleSelections.userId, user.id));

  console.log(`\n📦 Module Selections: ${selections.length}`);
  if (selections.length > 0) {
    const unlocked = selections.filter(s => s.status === "unlocked").length;
    console.log(`   Unlocked: ${unlocked}`);
    console.log(`   Pending: ${selections.length - unlocked}`);
  }

  console.log("\n✅ User is ready to login!");
}

checkUser()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error("❌ Error:", error);
    process.exit(1);
  });
