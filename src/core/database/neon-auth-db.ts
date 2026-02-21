/**
 * Neon Auth Database Connection
 * 
 * Connects to the neondb database (auto-created by Neon)
 * This is separate from the beelearnt application database
 * 
 * Database Structure:
 * - neondb (Neon Auth database)
 *   └── neon_auth schema
 *       ├── user (authentication identities)
 *       ├── account (OAuth providers, passwords)
 *       ├── session (active sessions)
 *       ├── organization (multi-tenant orgs)
 *       ├── member (org memberships)
 *       ├── invitation (org invitations)
 *       ├── verification (email/phone verification)
 *       ├── project_config (Neon Auth config)
 *       └── jwks (JWT signing keys)
 */

import { drizzle } from "drizzle-orm/neon-http";
import { neon } from "@neondatabase/serverless";
import { env } from "../../config/env.js";
import * as neonAuthSchema from "./neon-auth-schema.js";

if (!env.neonAuthDatabaseUrl) {
  console.warn("⚠️  NEON_AUTH_DATABASE_URL is not set. Neon Auth features will not work.");
  console.warn("   Set NEON_AUTH_DATABASE_URL to connect to the neondb database.");
}

// Create Neon Auth database connection (if available)
let neonAuthDb: ReturnType<typeof drizzle> | null = null;

if (env.neonAuthDatabaseUrl) {
  const neonAuthSql = neon(env.neonAuthDatabaseUrl, {
    fetchOptions: {
      timeout: env.neonFetchTimeoutMs,
    },
  });

  neonAuthDb = drizzle(neonAuthSql, { schema: neonAuthSchema });
  console.log("✓ Connected to Neon Auth database (neondb)");
} else {
  console.warn("✗ Neon Auth database not configured - using local auth only");
}

export const db = neonAuthDb;
export type NeonAuthDatabase = typeof db;

// Re-export schema for convenience
export { neonAuthSchema };
