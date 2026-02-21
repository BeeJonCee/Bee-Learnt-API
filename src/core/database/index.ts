import { drizzle } from "drizzle-orm/neon-http";
import { neon } from "@neondatabase/serverless";
import { env } from "../../config/env.js";
import * as schema from "./schema/index.js";

if (!env.databaseUrl) {
  throw new Error("DATABASE_URL is not set");
}

const sql = neon(env.databaseUrl, {
  fetchOptions: {
    timeout: env.neonFetchTimeoutMs,
  },
});

export const db = drizzle(sql, { schema });
export type Database = typeof db;

// Re-export schema for convenience
export { schema };
