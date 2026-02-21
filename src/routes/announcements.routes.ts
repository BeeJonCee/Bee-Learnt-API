import { Router } from "express";
import { create, list } from "../controllers/announcements.controller.js";
import { requireAuth, requireRole } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { announcementCreateSchema } from "../shared/validators/index.js";

const announcementsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Announcements
 *   description: Broadcast updates and announcements to the community
 */

/**
 * @swagger
 * /api/announcements:
 *   get:
 *     summary: List announcements available to the user
 *     tags: [Announcements]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Announcement feed
 */
announcementsRoutes.get("/", requireAuth, list);

/**
 * @swagger
 * /api/announcements:
 *   post:
 *     summary: Publish a new announcement
 *     tags: [Announcements]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       201:
 *         description: Announcement created
 */
announcementsRoutes.post(
  "/",
  requireRole(["ADMIN"]),
  validateBody(announcementCreateSchema),
  create
);

export { announcementsRoutes };
