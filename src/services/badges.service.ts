import { eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { badges, userBadges } from "../core/database/schema/index.js";

export async function listBadgesForUser(userId: string) {
  const [badgeRows, earnedRows] = await Promise.all([
    db.select().from(badges).orderBy(badges.id),
    db.select().from(userBadges).where(eq(userBadges.userId, userId)),
  ]);

  const earnedIds = new Set(earnedRows.map((row) => row.badgeId));

  return badgeRows.map((badge) => ({
    ...badge,
    earned: earnedIds.has(badge.id),
  }));
}
