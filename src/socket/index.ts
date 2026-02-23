import { Server as HttpServer } from "http";
import { Server, Socket } from "socket.io";
import { env } from "../config/env.js";
import { createLogger } from "../shared/utils/logger.js";
import { socketAuthMiddleware } from "./middleware/auth.js";
import { registerNotificationHandlers } from "./handlers/notifications.handler.js";
import { registerCollaborationHandlers } from "./handlers/collaboration.handler.js";

const logger = createLogger("socket");

let io: Server | null = null;

export function initializeSocket(httpServer: HttpServer): Server {
  const corsOrigin =
    env.corsOrigin === "*"
      ? "*"
      : env.corsOrigin.split(",").map((origin) => origin.trim());

  io = new Server(httpServer, {
    cors: {
      origin: corsOrigin,
      credentials: env.corsOrigin !== "*",
    },
    pingTimeout: 60000,
    pingInterval: 25000,
  });

  // Apply authentication middleware
  io.use(socketAuthMiddleware);

  io.on("connection", (socket: Socket) => {
    const user = socket.data.user as { id?: string; role?: string } | undefined;

    logger.info("Client connected", {
      socketId: socket.id,
      userId:   user?.id ?? "anonymous",
      role:     user?.role,
    });

    // Join user-specific room for targeted notifications
    if (user?.id) {
      socket.join(`user:${user.id}`);

      if (user.role) {
        socket.join(`role:${user.role}`);
        logger.debug("Socket joined rooms", {
          socketId: socket.id,
          rooms:    [`user:${user.id}`, `role:${user.role}`],
        });
      }
    }

    // Register event handlers
    registerNotificationHandlers(io!, socket);
    registerCollaborationHandlers(io!, socket);

    socket.on("disconnect", (reason) => {
      logger.info("Client disconnected", {
        socketId: socket.id,
        userId:   user?.id ?? "anonymous",
        reason,
      });
    });

    socket.on("error", (error) => {
      logger.error("Socket error", {
        socketId: socket.id,
        userId:   user?.id,
        error:    error instanceof Error ? error.message : String(error),
      });
    });
  });

  logger.info("Socket.io server initialised", {
    corsOrigin: typeof corsOrigin === "string" ? corsOrigin : corsOrigin.join(", "),
  });

  return io;
}

export function getIO(): Server {
  if (!io) {
    throw new Error("Socket.io not initialized. Call initializeSocket first.");
  }
  return io;
}

// ─── Utility emitters ─────────────────────────────────────────────────────────

export function emitToUser(userId: string, event: string, data: unknown): void {
  io?.to(`user:${userId}`).emit(event, data);
}

export function emitToRole(role: string, event: string, data: unknown): void {
  io?.to(`role:${role}`).emit(event, data);
}

export function emitToRoom(roomId: string, event: string, data: unknown): void {
  io?.to(`room:${roomId}`).emit(event, data);
}

export function emitToAll(event: string, data: unknown): void {
  io?.emit(event, data);
}
