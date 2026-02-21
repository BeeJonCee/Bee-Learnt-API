import { Router } from "express";
import { create, list } from "../controllers/events.controller.js";
import { requireAuth, requireRole } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { eventCreateSchema } from "../shared/validators/index.js";

const eventsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Events
 *   description: Community and classroom events
 */

/**
 * @swagger
 * /api/events:
 *   get:
 *     summary: List events available to the user
 *     tags: [Events]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Event collection
 */
eventsRoutes.get("/", requireAuth, list);

/**
 * @swagger
 * /api/events:
 *   post:
 *     summary: Create a new event
 *     tags: [Events]
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
 *         description: Event created
 */
eventsRoutes.post("/", requireRole(["ADMIN"]), validateBody(eventCreateSchema), create);

export { eventsRoutes };
