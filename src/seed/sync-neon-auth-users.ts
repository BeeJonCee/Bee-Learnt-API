import "dotenv/config";
import { db as authDb } from "../core/database/neon-auth-db.js";
import { neonAuthUsers } from "../core/database/neon-auth-schema.js";
import { syncUserFromNeonAuth } from "../services/neon-auth-sync.js";

async function run() {
  if (!authDb) {
    console.error("NEON_AUTH_DATABASE_URL is not set. Cannot sync users.");
    process.exit(1);
  }

  console.log("Syncing neondb.neon_auth.user -> beelearnt.public.users");

  const neonUsers = await authDb
    .select({ id: neonAuthUsers.id })
    .from(neonAuthUsers);

  if (neonUsers.length === 0) {
    console.log("No Neon Auth users found. Nothing to sync.");
    return;
  }

  let synced = 0;
  let failed = 0;

  for (const row of neonUsers) {
    try {
      await syncUserFromNeonAuth(row.id);
      synced += 1;
    } catch (error) {
      failed += 1;
      console.error(`Failed to sync user ${row.id}:`, error);
    }
  }

  console.log(`Sync complete: synced=${synced} failed=${failed}`);
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Sync failed:", error);
    process.exit(1);
  });
