import type { Server, Socket } from "socket.io";
import { logInfo, logError } from "../../shared/utils/logger.js";

export interface ChatMessage {
  id?: number;
  roomId: number;
  userId: string;
  userName?: string;
  content: string;
  createdAt: string;
}

export interface TypingIndicator {
  roomId: number;
  userId: string;
  userName?: string;
  isTyping: boolean;
}

export interface MemberPresence {
  roomId: number;
  userId: string;
  userName?: string;
  status: "online" | "offline" | "away";
}

// Track typing timeouts per user per room
const typingTimeouts = new Map<string, NodeJS.Timeout>();

export function registerCollaborationHandlers(io: Server, socket: Socket): void {
  const user = socket.data.user;

  // Join a collaboration room
  socket.on("room:join", async (roomId: number) => {
    if (!user?.id) {
      socket.emit("error", { message: "Unauthorized" });
      return;
    }

    const roomKey = `room:${roomId}`;
    socket.join(roomKey);

    logInfo(`User ${user.id} joined room ${roomId}`);

    // Notify other room members
    socket.to(roomKey).emit("member:online", {
      roomId,
      userId: user.id,
      userName: user.name,
      status: "online",
    } as MemberPresence);

    // Acknowledge join
    socket.emit("room:joined", { roomId });
  });

  // Leave a collaboration room
  socket.on("room:leave", (roomId: number) => {
    if (!user?.id) return;

    const roomKey = `room:${roomId}`;
    socket.leave(roomKey);

    logInfo(`User ${user.id} left room ${roomId}`);

    // Clear any typing indicators
    const typingKey = `${roomId}:${user.id}`;
    const timeout = typingTimeouts.get(typingKey);
    if (timeout) {
      clearTimeout(timeout);
      typingTimeouts.delete(typingKey);
    }

    // Notify other room members
    socket.to(roomKey).emit("member:offline", {
      roomId,
      userId: user.id,
      userName: user.name,
      status: "offline",
    } as MemberPresence);
  });

  // Send a message to a room
  socket.on("message:send", async (data: { roomId: number; content: string }) => {
    if (!user?.id) {
      socket.emit("error", { message: "Unauthorized" });
      return;
    }

    const { roomId, content } = data;
    const roomKey = `room:${roomId}`;

    const message: ChatMessage = {
      roomId,
      userId: user.id,
      userName: user.name,
      content,
      createdAt: new Date().toISOString(),
    };

    // Broadcast to all room members (including sender)
    io.to(roomKey).emit("message:receive", message);

    logInfo(`User ${user.id} sent message to room ${roomId}`);

    // Clear typing indicator for this user
    const typingKey = `${roomId}:${user.id}`;
    const timeout = typingTimeouts.get(typingKey);
    if (timeout) {
      clearTimeout(timeout);
      typingTimeouts.delete(typingKey);
      socket.to(roomKey).emit("typing:stop", {
        roomId,
        userId: user.id,
        userName: user.name,
        isTyping: false,
      } as TypingIndicator);
    }
  });

  // Typing indicator start
  socket.on("typing:start", (roomId: number) => {
    if (!user?.id) return;

    const roomKey = `room:${roomId}`;
    const typingKey = `${roomId}:${user.id}`;

    // Clear any existing timeout
    const existingTimeout = typingTimeouts.get(typingKey);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    // Broadcast typing indicator to other room members
    socket.to(roomKey).emit("typing:start", {
      roomId,
      userId: user.id,
      userName: user.name,
      isTyping: true,
    } as TypingIndicator);

    // Auto-stop typing after 3 seconds of inactivity
    const timeout = setTimeout(() => {
      socket.to(roomKey).emit("typing:stop", {
        roomId,
        userId: user.id,
        userName: user.name,
        isTyping: false,
      } as TypingIndicator);
      typingTimeouts.delete(typingKey);
    }, 3000);

    typingTimeouts.set(typingKey, timeout);
  });

  // Typing indicator stop
  socket.on("typing:stop", (roomId: number) => {
    if (!user?.id) return;

    const roomKey = `room:${roomId}`;
    const typingKey = `${roomId}:${user.id}`;

    // Clear timeout
    const timeout = typingTimeouts.get(typingKey);
    if (timeout) {
      clearTimeout(timeout);
      typingTimeouts.delete(typingKey);
    }

    // Broadcast stop typing
    socket.to(roomKey).emit("typing:stop", {
      roomId,
      userId: user.id,
      userName: user.name,
      isTyping: false,
    } as TypingIndicator);
  });

  // Handle disconnect - clean up room memberships
  socket.on("disconnect", () => {
    if (!user?.id) return;

    // Clean up all typing timeouts for this user
    for (const [key, timeout] of typingTimeouts.entries()) {
      if (key.endsWith(`:${user.id}`)) {
        clearTimeout(timeout);
        typingTimeouts.delete(key);
      }
    }
  });
}

// Server-side emit functions (to be called from services)
export function emitMessageToRoom(io: Server, roomId: number, message: ChatMessage): void {
  io.to(`room:${roomId}`).emit("message:receive", message);
}

export function emitRoomUpdate(io: Server, roomId: number, update: {
  type: "member_joined" | "member_left" | "room_updated";
  data: unknown;
}): void {
  io.to(`room:${roomId}`).emit("room:update", update);
}
