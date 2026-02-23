import { Router } from "express";
import { requireAuth, requireRole } from "../../core/middleware/auth.js";
import { asyncHandler } from "../../core/middleware/async-handler.js";
import type { Request, Response } from "express";
import { eq, desc, and, isNull, sql } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import { notifications, users, roles } from "../../core/database/schema/index.js";

const notificationsRoutes = Router();

/**
 * GET /api/notifications
 * Get notifications for the authenticated user.
 * Admin users also receive platform-wide notifications (type starts with "admin:").
 */
notificationsRoutes.get(
  "/",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const limit = Math.min(Number(req.query.limit) || 50, 100);

    const rows = await db
      .select()
      .from(notifications)
      .where(eq(notifications.userId, userId))
      .orderBy(desc(notifications.createdAt))
      .limit(limit);

    const unreadCount = rows.filter((n) => !n.readAt).length;

    res.json({ notifications: rows, unreadCount });
  }),
);

/**
 * GET /api/notifications/admin
 * Admin: get all recent notifications across all users for oversight.
 */
notificationsRoutes.get(
  "/admin",
  requireRole(["ADMIN"]),
  asyncHandler(async (req: Request, res: Response) => {
    const limit = Math.min(Number(req.query.limit) || 50, 100);

    const rows = await db
      .select({
        id: notifications.id,
        userId: notifications.userId,
        userName: users.name,
        type: notifications.type,
        title: notifications.title,
        message: notifications.message,
        readAt: notifications.readAt,
        createdAt: notifications.createdAt,
      })
      .from(notifications)
      .innerJoin(users, eq(notifications.userId, users.id))
      .orderBy(desc(notifications.createdAt))
      .limit(limit);

    res.json({ notifications: rows });
  }),
);

/**
 * PATCH /api/notifications/:id/read
 * Mark a notification as read.
 */
notificationsRoutes.patch(
  "/:id/read",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const notificationId = Number(req.params.id);

    if (!userId || isNaN(notificationId)) {
      res.status(400).json({ message: "Invalid request" });
      return;
    }

    await db
      .update(notifications)
      .set({ readAt: new Date() })
      .where(
        and(
          eq(notifications.id, notificationId),
          eq(notifications.userId, userId),
        ),
      );

    res.json({ message: "Marked as read" });
  }),
);

/**
 * POST /api/notifications/read-all
 * Mark all notifications as read for the authenticated user.
 */
notificationsRoutes.post(
  "/read-all",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    await db
      .update(notifications)
      .set({ readAt: new Date() })
      .where(
        and(
          eq(notifications.userId, userId),
          isNull(notifications.readAt),
        ),
      );

    res.json({ message: "All notifications marked as read" });
  }),
);

export { notificationsRoutes };
