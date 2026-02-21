import { Router } from "express";
import { requireAuth } from "../core/middleware/auth.js";
import { validateBody, validateQuery } from "../core/middleware/validate.js";
import { messageCreateSchema, messageListQuerySchema } from "../shared/validators/index.js";
import {
  listInboxHandler,
  listSentHandler,
  getMessageHandler,
  createMessageHandler,
  deleteMessageHandler,
  getUnreadCountHandler,
} from "../controllers/messaging.controller.js";

const messagingRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Messages
 *   description: Internal messaging between users
 */

messagingRoutes.use(requireAuth);

/**
 * @swagger
 * /api/messages:
 *   get:
 *     summary: List inbox messages
 *     tags: [Messages]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Inbox messages
 */
messagingRoutes.get(
  "/",
  validateQuery(messageListQuerySchema),
  listInboxHandler
);

/**
 * @swagger
 * /api/messages/sent:
 *   get:
 *     summary: List sent messages
 *     tags: [Messages]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Sent messages
 */
messagingRoutes.get("/sent", validateQuery(messageListQuerySchema), listSentHandler);

/**
 * @swagger
 * /api/messages/unread-count:
 *   get:
 *     summary: Get unread message count
 *     tags: [Messages]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Unread count
 */
messagingRoutes.get("/unread-count", getUnreadCountHandler);

/**
 * @swagger
 * /api/messages/{id}:
 *   get:
 *     summary: Get a single message (marks as read)
 *     tags: [Messages]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Message details
 */
messagingRoutes.get("/:id", getMessageHandler);

/**
 * @swagger
 * /api/messages:
 *   post:
 *     summary: Send a new message
 *     tags: [Messages]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [recipientId, subject, body]
 *             properties:
 *               recipientId:
 *                 type: string
 *               subject:
 *                 type: string
 *               body:
 *                 type: string
 *     responses:
 *       201:
 *         description: Message sent
 */
messagingRoutes.post("/", validateBody(messageCreateSchema), createMessageHandler);

/**
 * @swagger
 * /api/messages/{id}:
 *   delete:
 *     summary: Delete a message (soft delete)
 *     tags: [Messages]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Deleted
 */
messagingRoutes.delete("/:id", deleteMessageHandler);

export { messagingRoutes };
