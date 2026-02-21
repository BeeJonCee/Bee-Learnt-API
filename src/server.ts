import "dotenv/config";
import { createServer } from "http";
import { app } from "./app.js";
import { env } from "./config/env.js";
import { logInfo } from "./shared/utils/logger.js";
import { initializeSocket, getIO } from "./socket/index.js";

const port = env.port;
const host = "0.0.0.0"; // Listen on all network interfaces for deployment

// Create HTTP server and attach Socket.io
const httpServer = createServer(app);
initializeSocket(httpServer);

httpServer.listen(port, host, () => {
  logInfo(`BeeLearnt API listening on ${host}:${port}`);
  logInfo(`Socket.io server initialized`);
  logInfo(`Swagger docs available at http://localhost:${port}/api-docs`);
});

// Export for use in other modules
export { httpServer, getIO };
