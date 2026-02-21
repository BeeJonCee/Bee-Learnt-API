import { desc, eq, or } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { announcements } from "../core/database/schema/index.js";
import type { BeeLearntRole } from "../shared/types/auth.js";

export type AnnouncementInput = {
  title: string;
  body: string;
  audience: "ALL" | BeeLearntRole;
  pinned?: boolean;
  publishedAt?: string;
};

export async function listAnnouncements(role: BeeLearntRole, limit = 5) {
  return db
    .select()
    .from(announcements)
    .where(or(eq(announcements.audience, "ALL"), eq(announcements.audience, role)))
    .orderBy(desc(announcements.pinned), desc(announcements.publishedAt))
    .limit(limit);
}

export async function createAnnouncement(input: AnnouncementInput) {
  const [created] = await db
    .insert(announcements)
    .values({
      title: input.title,
      body: input.body,
      audience: input.audience,
      pinned: input.pinned ?? false,
      publishedAt: input.publishedAt ? new Date(input.publishedAt) : new Date(),
    })
    .returning();

  return created;
}
