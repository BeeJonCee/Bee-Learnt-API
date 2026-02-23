import { asc, sql } from "drizzle-orm";
import { env } from "../../config/env.js";
import { db as authDb } from "../../core/database/neon-auth-db.js";
import { neonAuthUsers } from "../../core/database/neon-auth-schema.js";
import { createLogger } from "../../shared/utils/logger.js";
import { syncUserFromNeonAuth } from "./neon-auth-sync.js";

const logger = createLogger("neon-auth-sync-worker");
const MISSING_NEON_AUTH_CODES = new Set(["42P01", "3F000"]);

type SyncCursor = {
  updatedAt: Date;
  id: string;
};

let timer: ReturnType<typeof setInterval> | null = null;
let running = false;
let cursor: SyncCursor | null = null;
let hasLoggedMissingNeonAuthTables = false;

function isMissingNeonAuthError(error: unknown) {
  const code = (error as { code?: string } | null)?.code;
  return Boolean(code && MISSING_NEON_AUTH_CODES.has(code));
}

function getWhereClause(nextCursor: SyncCursor | null) {
  if (!nextCursor) {
    return sql`TRUE`;
  }

  return sql`(
    ${neonAuthUsers.updatedAt} > ${nextCursor.updatedAt}
    OR (
      ${neonAuthUsers.updatedAt} = ${nextCursor.updatedAt}
      AND ${neonAuthUsers.id}::text > ${nextCursor.id}
    )
  )`;
}

async function runSyncCycle() {
  if (!authDb) {
    return;
  }

  if (running) {
    logger.warn("Previous sync cycle is still running; skipping tick");
    return;
  }

  running = true;
  const startedAt = Date.now();
  let scanned = 0;
  let synced = 0;
  let failed = 0;
  let localCursor = cursor;

  try {
    while (true) {
      const rows = await authDb
        .select({
          id: neonAuthUsers.id,
          updatedAt: neonAuthUsers.updatedAt,
        })
        .from(neonAuthUsers)
        .where(getWhereClause(localCursor))
        .orderBy(asc(neonAuthUsers.updatedAt), asc(neonAuthUsers.id))
        .limit(env.neonUserSyncBatchSize);

      if (rows.length === 0) {
        break;
      }

      for (const row of rows) {
        scanned += 1;
        try {
          const result = await syncUserFromNeonAuth(row.id);
          if (result) {
            synced += 1;
          }
        } catch (error) {
          failed += 1;
          logger.warn("Failed to sync user from Neon Auth", {
            userId: row.id,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }

      const tail = rows[rows.length - 1];
      localCursor = {
        updatedAt: tail.updatedAt,
        id: tail.id,
      };

      if (rows.length < env.neonUserSyncBatchSize) {
        break;
      }
    }

    cursor = localCursor;
    logger.info("Neon Auth user sync cycle complete", {
      scanned,
      synced,
      failed,
      durationMs: Date.now() - startedAt,
      cursorUpdatedAt: cursor?.updatedAt.toISOString(),
      cursorId: cursor?.id,
    });
  } catch (error) {
    if (isMissingNeonAuthError(error)) {
      if (!hasLoggedMissingNeonAuthTables) {
        hasLoggedMissingNeonAuthTables = true;
        logger.warn("Neon Auth tables are not ready yet; sync worker will retry on next interval", {
          error: error instanceof Error ? error.message : String(error),
          code: (error as { code?: string } | null)?.code,
        });
      }
      return;
    }

    logger.error("Neon Auth user sync cycle failed", {
      error: error instanceof Error ? error.message : String(error),
      durationMs: Date.now() - startedAt,
    });
  } finally {
    running = false;
  }
}

export function startNeonAuthUserSyncWorker() {
  if (!env.neonUserSyncEnabled) {
    logger.info("Neon Auth user sync worker is disabled by environment");
    return () => {};
  }

  if (!authDb || !env.neonAuthDatabaseUrl) {
    logger.info("Neon Auth user sync worker skipped (Neon Auth DB not configured)");
    return () => {};
  }

  if (timer) {
    logger.warn("Neon Auth user sync worker is already running");
    return () => stopNeonAuthUserSyncWorker();
  }

  logger.info("Starting Neon Auth user sync worker", {
    intervalMs: env.neonUserSyncIntervalMs,
    batchSize: env.neonUserSyncBatchSize,
  });

  void runSyncCycle();

  timer = setInterval(() => {
    void runSyncCycle();
  }, env.neonUserSyncIntervalMs);

  timer.unref();

  return () => stopNeonAuthUserSyncWorker();
}

export function stopNeonAuthUserSyncWorker() {
  if (!timer) return;

  clearInterval(timer);
  timer = null;
  logger.info("Stopped Neon Auth user sync worker");
}
