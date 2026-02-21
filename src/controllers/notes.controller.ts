import type { Request, Response } from "express";
import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { lessonNotes } from "../core/database/schema/index.js";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { lessonNoteQuerySchema } from "../shared/validators/index.js";

export const listNotes = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const parsed = lessonNoteQuerySchema.safeParse({
    lessonId: req.query.lessonId ? Number(req.query.lessonId) : undefined,
  });
  if (!parsed.success) {
    res.status(400).json({ message: "lessonId is required", issues: parsed.error.issues });
    return;
  }

  const notes = await db
    .select()
    .from(lessonNotes)
    .where(and(eq(lessonNotes.userId, userId), eq(lessonNotes.lessonId, parsed.data.lessonId)))
    .orderBy(lessonNotes.createdAt);

  res.json(notes);
});

export const createNote = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const { lessonId, content } = req.body as { lessonId: number; content: string };

  const [created] = await db
    .insert(lessonNotes)
    .values({
      userId,
      lessonId,
      content,
      updatedAt: new Date(),
    })
    .returning();

  res.status(201).json(created);
});
