import "dotenv/config";
import { eq, sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { db as authDb } from "../core/database/neon-auth-db.js";
import { roles, users } from "../core/database/schema/index.js";

/**
 * Migration script to set roles for existing users:
 * - j.chauke@outlook.com -> ADMIN
 * - john.t.chauke@outlook.com -> STUDENT
 * - spiderneon@yahoo.com -> PARENT
 *
 * Queries the neondb database (via authDb) for Neon Auth user records,
 * then syncs roles into the beelearnt database (via db/appDb).
 */

async function setUserRoles() {
  console.log("Starting user role assignment...\n");

  if (!authDb) {
    console.log("⚠️  NEON_AUTH_DATABASE_URL not set. Will only update beelearnt users.");
  }

  const userRoles: Array<{ email: string; role: "ADMIN" | "PARENT" | "STUDENT" }> = [
    { email: "j.chauke@outlook.com", role: "ADMIN" },
    { email: "john.t.chauke@outlook.com", role: "STUDENT" },
    { email: "spiderneon@yahoo.com", role: "PARENT" },
  ];

  for (const { email, role } of userRoles) {
    try {
      // Get the role ID
      const [roleRecord] = await db.select().from(roles).where(eq(roles.name, role));
      if (!roleRecord) {
        console.log(`❌ Role '${role}' not found in database. Creating...`);
        const [newRole] = await db
          .insert(roles)
          .values({ name: role, description: `${role} role` })
          .returning();
        console.log(`✅ Created role '${role}' with ID ${newRole.id}`);
      }

      const roleId = roleRecord?.id ?? (await db.select().from(roles).where(eq(roles.name, role)))[0].id;

      // Check if user exists in Neon Auth (neondb) database
      if (authDb) {
        const neonAuthUsers = await authDb.execute(
          sql`SELECT id, name, email, role FROM "user" WHERE LOWER(email) = LOWER(${email})`
        );

        if (!neonAuthUsers.rows || neonAuthUsers.rows.length === 0) {
          console.log(`⚠️  User '${email}' not found in neondb (user table)`);
          console.log(`   Please ensure the user has signed in at least once through Neon Auth.\n`);
          continue;
        }

        const neonUser = neonAuthUsers.rows[0] as { id: string; name: string; email: string; role: string };

        // Update Neon Auth user role in neondb
        await authDb.execute(
          sql`UPDATE "user" SET role = ${role}, "updatedAt" = NOW() WHERE id = ${neonUser.id}`
        );

        console.log(`✅ Updated neondb user '${email}' (ID: ${neonUser.id}) role to '${role}'`);

        // Check if user exists in BeeLearnt users table
        const [beeUser] = await db.select().from(users).where(eq(users.email, email));

        if (!beeUser) {
          // Create user in BeeLearnt users table
          const [created] = await db
            .insert(users)
            .values({
              id: neonUser.id,
              name: neonUser.name || email.split("@")[0],
              email: neonUser.email,
              roleId,
            })
            .returning();

          console.log(`✅ Created BeeLearnt user '${email}' (ID: ${created.id}) with role '${role}'`);
        } else {
          // Update existing BeeLearnt user
          await db
            .update(users)
            .set({
              roleId,
              id: neonUser.id, // Ensure sync with neondb
              updatedAt: new Date(),
            })
            .where(eq(users.email, email));

          console.log(`✅ Updated BeeLearnt user '${email}' (ID: ${beeUser.id}) role to '${role}'`);
        }
      } else {
        console.log(`⚠️  Skipping neondb lookup for '${email}' (authDb not configured)`);
      }

      console.log();
    } catch (error) {
      console.error(`❌ Error processing user '${email}':`, error);
      console.log();
    }
  }

  console.log("✅ User role assignment completed!\n");

  // Display final user list
  console.log("Current user roles:");
  console.log("===================");
  const allUsers = await db
    .select({
      id: users.id,
      email: users.email,
      name: users.name,
      role: roles.name,
    })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id));

  for (const user of allUsers) {
    console.log(`${user.email} (${user.name}) -> ${user.role}`);
  }
}

setUserRoles()
  .then(() => {
    console.log("\n✅ Script completed successfully");
    process.exit(0);
  })
  .catch((error) => {
    console.error("\n❌ Script failed:", error);
    process.exit(1);
  });
