import type { Request, Response } from "express";
import { eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { accessibilityPreferences } from "../core/database/schema/index.js";
import { asyncHandler } from "../core/middleware/async-handler.js";

const DEFAULT_PREFS = {
  textScale: 100,
  enableNarration: false,
  highContrast: false,
  language: "en",
  translationEnabled: false,
};

export const getAccessibility = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const [prefs] = await db
    .select()
    .from(accessibilityPreferences)
    .where(eq(accessibilityPreferences.userId, userId));

  res.json(prefs ?? DEFAULT_PREFS);
});

export const updateAccessibility = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const [existing] = await db
    .select()
    .from(accessibilityPreferences)
    .where(eq(accessibilityPreferences.userId, userId));

  if (existing) {
    const [updated] = await db
      .update(accessibilityPreferences)
      .set({ ...req.body, updatedAt: new Date() })
      .where(eq(accessibilityPreferences.userId, userId))
      .returning();
    res.json(updated);
    return;
  }

  const [created] = await db
    .insert(accessibilityPreferences)
    .values({
      userId,
      ...DEFAULT_PREFS,
      ...req.body,
      updatedAt: new Date(),
    })
    .returning();

  res.status(201).json(created);
});
