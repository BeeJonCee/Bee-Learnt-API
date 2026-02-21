import { and, desc, eq, isNull, or, sql } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { directMessages, users } from "../core/database/schema/index.js";

type ListMessagesInput = {
  userId: string;
  type: "inbox" | "sent";
  unreadOnly?: boolean;
  limit?: number;
  offset?: number;
};

type CreateMessageInput = {
  senderId: string;
  recipientId: string;
  subject?: string;
  content: string;
};

export async function listMessages(input: ListMessagesInput) {
  const conditions: any[] = [];

  if (input.type === "inbox") {
    conditions.push(eq(directMessages.recipientId, input.userId));
    conditions.push(eq(directMessages.deletedByRecipient, false));
    if (input.unreadOnly) {
      conditions.push(isNull(directMessages.readAt));
    }
  } else {
    conditions.push(eq(directMessages.senderId, input.userId));
    conditions.push(eq(directMessages.deletedBySender, false));
  }

  const limit = input.limit ?? 50;
  const offset = input.offset ?? 0;

  // We need to join with users to get sender/recipient names
  const senderAlias = db
    .select({
      id: users.id,
      name: users.name,
      email: users.email,
      image: users.image,
    })
    .from(users)
    .as("sender");

  const recipientAlias = db
    .select({
      id: users.id,
      name: users.name,
      email: users.email,
      image: users.image,
    })
    .from(users)
    .as("recipient");

  const items = await db
    .select({
      id: directMessages.id,
      senderId: directMessages.senderId,
      senderName: sql<string>`sender.name`,
      senderEmail: sql<string>`sender.email`,
      senderImage: sql<string | null>`sender.image`,
      recipientId: directMessages.recipientId,
      recipientName: sql<string>`recipient.name`,
      recipientEmail: sql<string>`recipient.email`,
      recipientImage: sql<string | null>`recipient.image`,
      subject: directMessages.subject,
      content: directMessages.content,
      readAt: directMessages.readAt,
      createdAt: directMessages.createdAt,
    })
    .from(directMessages)
    .innerJoin(
      sql`${users} as sender`,
      sql`sender.id = ${directMessages.senderId}`
    )
    .innerJoin(
      sql`${users} as recipient`,
      sql`recipient.id = ${directMessages.recipientId}`
    )
    .where(and(...conditions))
    .orderBy(desc(directMessages.createdAt))
    .limit(limit)
    .offset(offset);

  // Get total count
  let countQuery = db
    .select({ count: sql<number>`count(*)::int` })
    .from(directMessages)
    .where(and(...conditions));

  const [{ count }] = await countQuery;

  return { items, total: count, limit, offset };
}

export async function getMessageById(id: number, userId: string) {
  const [message] = await db
    .select({
      id: directMessages.id,
      senderId: directMessages.senderId,
      senderName: sql<string>`sender.name`,
      senderEmail: sql<string>`sender.email`,
      recipientId: directMessages.recipientId,
      recipientName: sql<string>`recipient.name`,
      recipientEmail: sql<string>`recipient.email`,
      subject: directMessages.subject,
      content: directMessages.content,
      readAt: directMessages.readAt,
      deletedBySender: directMessages.deletedBySender,
      deletedByRecipient: directMessages.deletedByRecipient,
      createdAt: directMessages.createdAt,
    })
    .from(directMessages)
    .innerJoin(
      sql`${users} as sender`,
      sql`sender.id = ${directMessages.senderId}`
    )
    .innerJoin(
      sql`${users} as recipient`,
      sql`recipient.id = ${directMessages.recipientId}`
    )
    .where(
      and(
        eq(directMessages.id, id),
        or(
          eq(directMessages.senderId, userId),
          eq(directMessages.recipientId, userId)
        )
      )
    );

  return message ?? null;
}

export async function createMessage(input: CreateMessageInput) {
  const [created] = await db
    .insert(directMessages)
    .values({
      senderId: input.senderId,
      recipientId: input.recipientId,
      subject: input.subject ?? null,
      content: input.content,
    })
    .returning();

  return created;
}

export async function markAsRead(id: number, userId: string) {
  const [updated] = await db
    .update(directMessages)
    .set({ readAt: new Date() })
    .where(
      and(
        eq(directMessages.id, id),
        eq(directMessages.recipientId, userId),
        isNull(directMessages.readAt)
      )
    )
    .returning();

  return updated ?? null;
}

export async function deleteMessage(id: number, userId: string) {
  // Get message to determine if user is sender or recipient
  const [message] = await db
    .select()
    .from(directMessages)
    .where(eq(directMessages.id, id));

  if (!message) return null;

  if (message.senderId === userId) {
    // Sender is deleting
    const [updated] = await db
      .update(directMessages)
      .set({ deletedBySender: true })
      .where(eq(directMessages.id, id))
      .returning();
    return updated;
  } else if (message.recipientId === userId) {
    // Recipient is deleting
    const [updated] = await db
      .update(directMessages)
      .set({ deletedByRecipient: true })
      .where(eq(directMessages.id, id))
      .returning();
    return updated;
  }

  return null;
}

export async function getUnreadCount(userId: string) {
  const [result] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(directMessages)
    .where(
      and(
        eq(directMessages.recipientId, userId),
        isNull(directMessages.readAt),
        eq(directMessages.deletedByRecipient, false)
      )
    );

  return result.count;
}
