import { Server as HttpServer } from "http";
import { Server, Socket } from "socket.io";
import { env } from "../config/env.js";
import { socketAuthMiddleware } from "./middleware/auth.js";
import { registerNotificationHandlers } from "./handlers/notifications.handler.js";
import { registerCollaborationHandlers } from "./handlers/collaboration.handler.js";
import { logInfo, logError } from "../shared/utils/logger.js";

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
    const user = socket.data.user;
    logInfo(`Socket connected: ${socket.id} (user: ${user?.id || "anonymous"})`);

    // Join user-specific room for targeted notifications
    if (user?.id) {
      socket.join(`user:${user.id}`);

      // Join role-specific room for announcements
      if (user.role) {
        socket.join(`role:${user.role}`);
      }
    }

    // Register event handlers
    registerNotificationHandlers(io!, socket);
    registerCollaborationHandlers(io!, socket);

    // Handle disconnection
    socket.on("disconnect", (reason) => {
      logInfo(`Socket disconnected: ${socket.id} (reason: ${reason})`);
    });

    // Handle errors
    socket.on("error", (error) => {
      logError(`Socket error: ${socket.id}`, { message: String(error) });
    });
  });

  return io;
}

export function getIO(): Server {
  if (!io) {
    throw new Error("Socket.io not initialized. Call initializeSocket first.");
  }
  return io;
}

// Utility functions for emitting events
export function emitToUser(userId: string, event: string, data: unknown): void {
  if (io) {
    io.to(`user:${userId}`).emit(event, data);
  }
}

export function emitToRole(role: string, event: string, data: unknown): void {
  if (io) {
    io.to(`role:${role}`).emit(event, data);
  }
}

export function emitToRoom(roomId: string, event: string, data: unknown): void {
  if (io) {
    io.to(`room:${roomId}`).emit(event, data);
  }
}

export function emitToAll(event: string, data: unknown): void {
  if (io) {
    io.emit(event, data);
  }
}
