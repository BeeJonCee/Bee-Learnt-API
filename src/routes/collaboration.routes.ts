import { Router } from "express";
import {
  createRoom,
  listRooms,
  getRoom,
  getMessages,
  sendMessage,
  getMembers,
  joinRoom,
  leaveRoom,
} from "../controllers/collaboration.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { z } from "zod";

const collaborationRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Collaboration
 *   description: Real-time collaboration spaces for learners and tutors
 */

const roomSchema = z.object({
  title: z.string().min(3),
  type: z.enum(["classroom", "project", "discussion", "breakout"]),
  description: z.string().optional(),
});

const messageSchema = z.object({
  content: z.string().min(1).max(2000),
});

// Room endpoints

/**
 * @swagger
 * /api/collaboration/rooms:
 *   get:
 *     summary: List collaboration rooms available to the user
 *     tags: [Collaboration]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Collaboration rooms
 */
collaborationRoutes.get("/rooms", requireAuth, listRooms);

/**
 * @swagger
 * /api/collaboration/rooms:
 *   post:
 *     summary: Create a new collaboration room
 *     tags: [Collaboration]
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
 *         description: Room created
 */
collaborationRoutes.post("/rooms", requireAuth, validateBody(roomSchema), createRoom);

/**
 * @swagger
 * /api/collaboration/rooms/{roomId}:
 *   get:
 *     summary: Fetch details for a collaboration room
 *     tags: [Collaboration]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: roomId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Room details
 *       404:
 *         description: Room not found
 */
collaborationRoutes.get("/rooms/:roomId", requireAuth, getRoom);

// Message endpoints

/**
 * @swagger
 * /api/collaboration/rooms/{roomId}/messages:
 *   get:
 *     summary: Retrieve messages for a room
 *     tags: [Collaboration]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: roomId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Message list
 */
collaborationRoutes.get("/rooms/:roomId/messages", requireAuth, getMessages);

/**
 * @swagger
 * /api/collaboration/rooms/{roomId}/messages:
 *   post:
 *     summary: Send a message to the room
 *     tags: [Collaboration]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: roomId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       201:
 *         description: Message sent
 */
collaborationRoutes.post("/rooms/:roomId/messages", requireAuth, validateBody(messageSchema), sendMessage);

// Member endpoints

/**
 * @swagger
 * /api/collaboration/rooms/{roomId}/members:
 *   get:
 *     summary: List members within a room
 *     tags: [Collaboration]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: roomId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Member roster
 */
collaborationRoutes.get("/rooms/:roomId/members", requireAuth, getMembers);

/**
 * @swagger
 * /api/collaboration/rooms/{roomId}/join:
 *   post:
 *     summary: Join a collaboration room
 *     tags: [Collaboration]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: roomId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Joined room successfully
 */
collaborationRoutes.post("/rooms/:roomId/join", requireAuth, joinRoom);

/**
 * @swagger
 * /api/collaboration/rooms/{roomId}/leave:
 *   post:
 *     summary: Leave a collaboration room
 *     tags: [Collaboration]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: roomId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Left room successfully
 */
collaborationRoutes.post("/rooms/:roomId/leave", requireAuth, leaveRoom);

export { collaborationRoutes };
