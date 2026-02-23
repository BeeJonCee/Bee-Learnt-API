import "dotenv/config";
import { createServer } from "http";
import { app } from "./app.js";
import { bootstrap } from "./bootstrap.js";
import { env } from "./config/env.js";
import { startNeonAuthUserSyncWorker } from "./modules/auth/neon-auth-sync.worker.js";
import { createLogger } from "./shared/utils/logger.js";
import { initializeSocket, getIO } from "./socket/index.js";

const logger = createLogger("server");
let stopNeonAuthUserSyncWorker: (() => void) | null = null;

const port = env.port;
const host = "0.0.0.0";

// ─── HTTP server ──────────────────────────────────────────────────────────────

const httpServer = createServer(app);
initializeSocket(httpServer);

// ─── Startup sequence ─────────────────────────────────────────────────────────

bootstrap()
  .then(() => {
    httpServer.listen(port, host, () => {
      stopNeonAuthUserSyncWorker = startNeonAuthUserSyncWorker();
      logger.info("BeeLearnt API is ready", {
        host,
        port,
        env:      env.nodeEnv,
        docsUrl:  `http://localhost:${port}/api-docs`,
        healthUrl:`http://localhost:${port}/health`,
      });
    });
  })
  .catch((err) => {
    logger.fatal("Bootstrap failed — server will not start", {
      error: err instanceof Error ? err.message : String(err),
      stack: err instanceof Error ? err.stack  : undefined,
    });
    process.exit(1);
  });

// ─── Graceful shutdown ────────────────────────────────────────────────────────

function shutdown(signal: string): void {
  logger.info(`${signal} received — shutting down gracefully`);

  if (stopNeonAuthUserSyncWorker) {
    stopNeonAuthUserSyncWorker();
    stopNeonAuthUserSyncWorker = null;
  }

  httpServer.close((err) => {
    if (err) {
      logger.error("Error during HTTP server close", {
        error: err.message,
      });
      process.exit(1);
    }
    logger.info("HTTP server closed");
    process.exit(0);
  });

  // Force kill after 10 s if connections keep hanging
  setTimeout(() => {
    logger.warn("Forceful shutdown after timeout");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT",  () => shutdown("SIGINT"));

// ─── Unhandled rejections / exceptions ───────────────────────────────────────

process.on("unhandledRejection", (reason) => {
  logger.error("Unhandled promise rejection", {
    reason: reason instanceof Error ? reason.message : String(reason),
    stack:  reason instanceof Error ? reason.stack   : undefined,
  });
});

process.on("uncaughtException", (err) => {
  logger.fatal("Uncaught exception — process will exit", {
    error: err.message,
    stack: err.stack,
  });
  process.exit(1);
});

// ─── Exports ──────────────────────────────────────────────────────────────────

export { httpServer, getIO };
