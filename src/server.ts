import "dotenv/config";
import { createServer } from "http";
import { app } from "./app.js";
import { bootstrap } from "./bootstrap.js";
import { env } from "./config/env.js";
import { logInfo, logError } from "./shared/utils/logger.js";
import { initializeSocket, getIO } from "./socket/index.js";

const port = env.port;
const host = "0.0.0.0"; // Listen on all network interfaces for deployment

// Create HTTP server and attach Socket.io
const httpServer = createServer(app);
initializeSocket(httpServer);

// Run migrations (+ optional seeders) then start the server
bootstrap()
  .then(() => {
    httpServer.listen(port, host, () => {
      logInfo(`BeeLearnt API listening on ${host}:${port}`);
      logInfo(`Socket.io server initialized`);
      logInfo(`Swagger docs available at http://localhost:${port}/api-docs`);
    });
  })
  .catch((err) => {
    logError("Bootstrap failed — server not started", {
      error: err instanceof Error ? err.message : String(err),
    });
    process.exit(1);
  });

// Export for use in other modules
export { httpServer, getIO };
