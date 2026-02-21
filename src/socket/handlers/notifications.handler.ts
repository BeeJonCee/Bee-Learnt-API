import type { Server, Socket } from "socket.io";
import { eq, and } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import { notifications, users, roles } from "../../core/database/schema/index.js";
import { logInfo } from "../../shared/utils/logger.js";

export interface NotificationPayload {
  id: number;
  type: string;
  title: string;
  message?: string;
  createdAt: string;
  data?: Record<string, unknown>;
}

export interface BadgeAwardedPayload {
  badgeId: number;
  badgeName: string;
  description?: string;
  awardedAt: string;
}

export interface LeaderboardUpdatePayload {
  userId: string;
  newRank: number;
  previousRank: number;
  score: number;
}

export function registerNotificationHandlers(io: Server, socket: Socket): void {
  const user = socket.data.user;

  // Mark notification as read
  socket.on("notification:read", async (notificationId: number) => {
    if (!user?.id) {
      socket.emit("error", { message: "Unauthorized" });
      return;
    }

    try {
      await db
        .update(notifications)
        .set({ readAt: new Date() })
        .where(
          and(
            eq(notifications.id, notificationId),
            eq(notifications.userId, user.id),
          ),
        );
    } catch {
      // Non-critical — just log
    }

    logInfo(`User ${user.id} marked notification ${notificationId} as read`);
    socket.emit("notification:read:ack", { notificationId, readAt: new Date().toISOString() });
  });

  // Subscribe to specific notification types
  socket.on("notification:subscribe", (types: string[]) => {
    if (!user?.id) return;

    for (const type of types) {
      socket.join(`notification:${type}`);
    }
    logInfo(`User ${user.id} subscribed to notification types: ${types.join(", ")}`);
  });

  // Unsubscribe from notification types
  socket.on("notification:unsubscribe", (types: string[]) => {
    if (!user?.id) return;

    for (const type of types) {
      socket.leave(`notification:${type}`);
    }
  });
}

// ─── Persist + emit helpers ────────────────────────────────────

async function persistNotification(
  userId: string,
  type: string,
  title: string,
  message?: string,
): Promise<number> {
  try {
    const [row] = await db
      .insert(notifications)
      .values({ userId, type, title, message })
      .returning({ id: notifications.id });
    return row.id;
  } catch {
    return Date.now(); // fallback ID if DB insert fails
  }
}

/**
 * Emit a notification to a user and persist it in the DB.
 * Also sends a copy to all ADMIN users for oversight.
 */
export async function emitNotification(
  io: Server,
  userId: string,
  notification: NotificationPayload,
): Promise<void> {
  // Persist
  const dbId = await persistNotification(
    userId,
    notification.type,
    notification.title,
    notification.message,
  );

  const payload: NotificationPayload = { ...notification, id: dbId };

  // Emit to the target user
  io.to(`user:${userId}`).emit("notification:new", payload);
  logInfo(`Emitted notification to user ${userId}: ${notification.title}`);

  // Also notify admins (they see all platform activity)
  io.to("role:ADMIN").emit("notification:new", {
    ...payload,
    type: `admin:${notification.type}`,
    title: `[User Activity] ${notification.title}`,
  });
}

export function emitBadgeAwarded(io: Server, userId: string, badge: BadgeAwardedPayload): void {
  io.to(`user:${userId}`).emit("badge:awarded", badge);
  logInfo(`Emitted badge award to user ${userId}: ${badge.badgeName}`);

  // Persist as notification
  persistNotification(
    userId,
    "badge",
    `Badge earned: ${badge.badgeName}`,
    badge.description,
  );
}

export function emitLeaderboardUpdate(io: Server, userId: string, update: LeaderboardUpdatePayload): void {
  io.to(`user:${userId}`).emit("leaderboard:update", update);
}

export function emitAnnouncementToRole(io: Server, role: string, announcement: {
  id: number;
  title: string;
  body: string;
  publishedAt: string;
}): void {
  io.to(`role:${role}`).emit("announcement:new", announcement);
  logInfo(`Emitted announcement to role ${role}: ${announcement.title}`);
}

export function emitAnnouncementToAll(io: Server, announcement: {
  id: number;
  title: string;
  body: string;
  publishedAt: string;
}): void {
  io.emit("announcement:new", announcement);
  logInfo(`Emitted announcement to all: ${announcement.title}`);
}
