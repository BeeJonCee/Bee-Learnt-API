import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber } from "../shared/utils/parse.js";
import {
  listMessages,
  getMessageById,
  createMessage,
  markAsRead,
  deleteMessage,
  getUnreadCount,
} from "../services/messaging.service.js";

export const listInboxHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const { unreadOnly, limit, offset } = req.query;

  const result = await listMessages({
    userId,
    type: "inbox",
    unreadOnly: unreadOnly === "true",
    limit: limit ? Number(limit) : undefined,
    offset: offset ? Number(offset) : undefined,
  });

  res.json(result);
});

export const listSentHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const { limit, offset } = req.query;

  const result = await listMessages({
    userId,
    type: "sent",
    limit: limit ? Number(limit) : undefined,
    offset: offset ? Number(offset) : undefined,
  });

  res.json(result);
});

export const getMessageHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const id = parseNumber(req.params.id as string);

  if (!id) {
    res.status(400).json({ message: "Invalid message ID" });
    return;
  }

  const message = await getMessageById(id, userId);
  if (!message) {
    res.status(404).json({ message: "Message not found" });
    return;
  }

  // Mark as read if recipient is viewing
  if (message.recipientId === userId && !message.readAt) {
    await markAsRead(id, userId);
    message.readAt = new Date();
  }

  res.json(message);
});

export const createMessageHandler = asyncHandler(async (req, res) => {
  const senderId = req.user!.id;
  const { recipientId, subject, content } = req.body;

  if (senderId === recipientId) {
    res.status(400).json({ message: "Cannot send message to yourself" });
    return;
  }

  const created = await createMessage({
    senderId,
    recipientId,
    subject,
    content,
  });

  res.status(201).json(created);
});

export const deleteMessageHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const id = parseNumber(req.params.id as string);

  if (!id) {
    res.status(400).json({ message: "Invalid message ID" });
    return;
  }

  const message = await getMessageById(id, userId);
  if (!message) {
    res.status(404).json({ message: "Message not found" });
    return;
  }

  await deleteMessage(id, userId);
  res.json({ message: "Message deleted" });
});

export const getUnreadCountHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const count = await getUnreadCount(userId);
  res.json({ count });
});
