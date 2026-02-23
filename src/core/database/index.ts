import { drizzle } from "drizzle-orm/neon-http";
import { neon } from "@neondatabase/serverless";
import { env } from "../../config/env.js";
import { createLogger } from "../../shared/utils/logger.js";
import * as schema from "./schema/index.js";

const logger = createLogger("database");

if (!env.databaseUrl) {
  logger.fatal("DATABASE_URL is not set — cannot initialise database client");
  throw new Error("DATABASE_URL is not set");
}

const sql = neon(env.databaseUrl, {
  fetchOptions: {
    timeout: env.neonFetchTimeoutMs,
  },
});

export const db = drizzle(sql, { schema });
export type Database = typeof db;

logger.debug("Database client initialised", {
  timeoutMs: env.neonFetchTimeoutMs,
});

// Re-export schema for convenience
export { schema };
