import type { Request, Response } from "express";
import { asyncHandler } from "../../core/middleware/async-handler.js";
import {
  listMessages,
  getMessageById,
  createMessage,
  markAsRead,
  deleteMessage,
  getUnreadCount,
} from "./messaging.service.js";

export const listInboxHandler = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const limit = req.query.limit ? Number(req.query.limit as string) : 50;
  const page = req.query.page ? Number(req.query.page as string) : 1;
  const offset = (page - 1) * limit;

  const result = await listMessages({ userId, type: "inbox", limit, offset });
  res.json(result);
});

export const listSentHandler = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const limit = req.query.limit ? Number(req.query.limit as string) : 50;
  const page = req.query.page ? Number(req.query.page as string) : 1;
  const offset = (page - 1) * limit;

  const result = await listMessages({ userId, type: "sent", limit, offset });
  res.json(result);
});

export const getMessageHandler = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const id = Number(req.params.id as string);
  if (Number.isNaN(id)) {
    res.status(400).json({ message: "Invalid message ID" });
    return;
  }

  const message = await getMessageById(id, userId);
  if (!message) {
    res.status(404).json({ message: "Message not found" });
    return;
  }

  // Mark as read if recipient
  if (message.recipientId === userId && !message.readAt) {
    await markAsRead(id, userId);
  }

  res.json(message);
});

export const createMessageHandler = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const { recipientId, subject, body } = req.body as {
    recipientId: string;
    subject?: string;
    body: string;
  };

  const message = await createMessage({
    senderId: userId,
    recipientId,
    subject,
    content: body,
  });

  res.status(201).json(message);
});

export const deleteMessageHandler = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const id = Number(req.params.id as string);
  if (Number.isNaN(id)) {
    res.status(400).json({ message: "Invalid message ID" });
    return;
  }

  const result = await deleteMessage(id, userId);
  if (!result) {
    res.status(404).json({ message: "Message not found or access denied" });
    return;
  }

  res.status(204).send();
});

export const getUnreadCountHandler = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const count = await getUnreadCount(userId);
  res.json({ count });
});
