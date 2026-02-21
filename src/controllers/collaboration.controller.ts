import type { Request, Response } from "express";
import { and, desc, eq, inArray, lt } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { collaborationMembers, collaborationMessages, collaborationRooms, users } from "../core/database/schema/index.js";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { getIO } from "../socket/index.js";
import { emitMessageToRoom } from "../socket/handlers/collaboration.handler.js";

export const listRooms = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const ownedRooms = await db
    .select()
    .from(collaborationRooms)
    .where(eq(collaborationRooms.ownerId, userId));

  const memberRooms = await db
    .select({ roomId: collaborationMembers.roomId })
    .from(collaborationMembers)
    .where(eq(collaborationMembers.userId, userId));

  const roomIds = Array.from(new Set(memberRooms.map((row) => row.roomId)));
  const memberRoomEntries =
    roomIds.length > 0
      ? await db.select().from(collaborationRooms).where(inArray(collaborationRooms.id, roomIds))
      : [];

  const uniqueMap = new Map<number, typeof ownedRooms[number]>();
  [...ownedRooms, ...memberRoomEntries].forEach((room) => {
    uniqueMap.set(room.id, room);
  });

  res.json(Array.from(uniqueMap.values()));
});

export const createRoom = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const { title, type, description } = req.body as {
    title: string;
    type: "classroom" | "project" | "discussion" | "breakout";
    description?: string;
  };

  const [created] = await db
    .insert(collaborationRooms)
    .values({
      title,
      type,
      ownerId: userId,
      description,
    })
    .returning();

  await db.insert(collaborationMembers).values({
    roomId: created.id,
    userId,
    role: "owner",
  });

  res.status(201).json(created);
});

// Get room details
export const getRoom = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const roomId = Number(req.params.roomId);
  if (Number.isNaN(roomId)) {
    res.status(400).json({ message: "Invalid room ID" });
    return;
  }

  // Check if user is a member
  const membership = await db
    .select()
    .from(collaborationMembers)
    .where(
      and(
        eq(collaborationMembers.roomId, roomId),
        eq(collaborationMembers.userId, userId)
      )
    )
    .limit(1);

  const room = await db
    .select()
    .from(collaborationRooms)
    .where(eq(collaborationRooms.id, roomId))
    .limit(1);

  if (room.length === 0) {
    res.status(404).json({ message: "Room not found" });
    return;
  }

  // Allow if owner or member
  if (room[0].ownerId !== userId && membership.length === 0) {
    res.status(403).json({ message: "Not a member of this room" });
    return;
  }

  res.json(room[0]);
});

// Get messages for a room
export const getMessages = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const roomId = Number(req.params.roomId);
  if (Number.isNaN(roomId)) {
    res.status(400).json({ message: "Invalid room ID" });
    return;
  }

  // Check membership
  const membership = await db
    .select()
    .from(collaborationMembers)
    .where(
      and(
        eq(collaborationMembers.roomId, roomId),
        eq(collaborationMembers.userId, userId)
      )
    )
    .limit(1);

  const room = await db
    .select()
    .from(collaborationRooms)
    .where(eq(collaborationRooms.id, roomId))
    .limit(1);

  if (room.length === 0) {
    res.status(404).json({ message: "Room not found" });
    return;
  }

  if (room[0].ownerId !== userId && membership.length === 0) {
    res.status(403).json({ message: "Not a member of this room" });
    return;
  }

  // Get messages with pagination
  const limit = Math.min(50, Number(req.query.limit) || 50);
  const before = req.query.before ? Number(req.query.before) : undefined;

  let query = db
    .select({
      id: collaborationMessages.id,
      roomId: collaborationMessages.roomId,
      userId: collaborationMessages.userId,
      userName: users.name,
      content: collaborationMessages.content,
      createdAt: collaborationMessages.createdAt,
    })
    .from(collaborationMessages)
    .leftJoin(users, eq(collaborationMessages.userId, users.id))
    .where(eq(collaborationMessages.roomId, roomId))
    .orderBy(desc(collaborationMessages.createdAt))
    .limit(limit);

  if (before) {
    query = db
      .select({
        id: collaborationMessages.id,
        roomId: collaborationMessages.roomId,
        userId: collaborationMessages.userId,
        userName: users.name,
        content: collaborationMessages.content,
        createdAt: collaborationMessages.createdAt,
      })
      .from(collaborationMessages)
      .leftJoin(users, eq(collaborationMessages.userId, users.id))
      .where(
        and(
          eq(collaborationMessages.roomId, roomId),
          lt(collaborationMessages.id, before)
        )
      )
      .orderBy(desc(collaborationMessages.createdAt))
      .limit(limit);
  }

  const messages = await query;

  // Return in chronological order
  res.json(messages.reverse());
});

// Send a message to a room
export const sendMessage = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const roomId = Number(req.params.roomId);
  if (Number.isNaN(roomId)) {
    res.status(400).json({ message: "Invalid room ID" });
    return;
  }

  const { content } = req.body as { content: string };
  if (!content || content.trim().length === 0) {
    res.status(400).json({ message: "Message content is required" });
    return;
  }

  // Check membership
  const membership = await db
    .select()
    .from(collaborationMembers)
    .where(
      and(
        eq(collaborationMembers.roomId, roomId),
        eq(collaborationMembers.userId, userId)
      )
    )
    .limit(1);

  const room = await db
    .select()
    .from(collaborationRooms)
    .where(eq(collaborationRooms.id, roomId))
    .limit(1);

  if (room.length === 0) {
    res.status(404).json({ message: "Room not found" });
    return;
  }

  if (room[0].ownerId !== userId && membership.length === 0) {
    res.status(403).json({ message: "Not a member of this room" });
    return;
  }

  // Get user name
  const user = await db
    .select({ name: users.name })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  // Create message
  const [message] = await db
    .insert(collaborationMessages)
    .values({
      roomId,
      userId,
      content: content.trim(),
    })
    .returning();

  const messageData = {
    id: message.id,
    roomId: message.roomId,
    userId: message.userId,
    userName: user[0]?.name ?? "Unknown",
    content: message.content,
    createdAt: message.createdAt.toISOString(),
  };

  // Emit to room via Socket.io
  try {
    const io = getIO();
    emitMessageToRoom(io, roomId, messageData);
  } catch {
    // Socket not available
  }

  res.status(201).json(messageData);
});

// Get room members
export const getMembers = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const roomId = Number(req.params.roomId);
  if (Number.isNaN(roomId)) {
    res.status(400).json({ message: "Invalid room ID" });
    return;
  }

  const members = await db
    .select({
      userId: collaborationMembers.userId,
      userName: users.name,
      userEmail: users.email,
      role: collaborationMembers.role,
      joinedAt: collaborationMembers.joinedAt,
    })
    .from(collaborationMembers)
    .leftJoin(users, eq(collaborationMembers.userId, users.id))
    .where(eq(collaborationMembers.roomId, roomId));

  res.json(members);
});

// Join a room
export const joinRoom = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const roomId = Number(req.params.roomId);
  if (Number.isNaN(roomId)) {
    res.status(400).json({ message: "Invalid room ID" });
    return;
  }

  // Check if room exists
  const room = await db
    .select()
    .from(collaborationRooms)
    .where(eq(collaborationRooms.id, roomId))
    .limit(1);

  if (room.length === 0) {
    res.status(404).json({ message: "Room not found" });
    return;
  }

  // Check if already a member
  const existing = await db
    .select()
    .from(collaborationMembers)
    .where(
      and(
        eq(collaborationMembers.roomId, roomId),
        eq(collaborationMembers.userId, userId)
      )
    )
    .limit(1);

  if (existing.length > 0) {
    res.json({ message: "Already a member" });
    return;
  }

  // Add as member
  await db.insert(collaborationMembers).values({
    roomId,
    userId,
    role: "member",
  });

  res.status(201).json({ message: "Joined room successfully" });
});

// Leave a room
export const leaveRoom = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const roomId = Number(req.params.roomId);
  if (Number.isNaN(roomId)) {
    res.status(400).json({ message: "Invalid room ID" });
    return;
  }

  // Check if room owner (can't leave own room)
  const room = await db
    .select()
    .from(collaborationRooms)
    .where(eq(collaborationRooms.id, roomId))
    .limit(1);

  if (room.length > 0 && room[0].ownerId === userId) {
    res.status(400).json({ message: "Owner cannot leave the room" });
    return;
  }

  // Remove membership
  await db
    .delete(collaborationMembers)
    .where(
      and(
        eq(collaborationMembers.roomId, roomId),
        eq(collaborationMembers.userId, userId)
      )
    );

  res.json({ message: "Left room successfully" });
});
