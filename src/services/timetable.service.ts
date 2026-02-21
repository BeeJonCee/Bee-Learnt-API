import { and, eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { timetableEntries, subjects } from "../core/database/schema/index.js";

export type DayOfWeek =
  | "monday"
  | "tuesday"
  | "wednesday"
  | "thursday"
  | "friday"
  | "saturday"
  | "sunday";

type CreateEntryInput = {
  userId: string;
  subjectId?: number;
  title: string;
  dayOfWeek: DayOfWeek;
  startTime: string;
  endTime: string;
  location?: string;
  color?: string;
  isRecurring?: boolean;
};

type UpdateEntryInput = Partial<Omit<CreateEntryInput, "userId">>;

export async function listEntries(userId: string) {
  const dayOrder = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
  ];

  const entries = await db
    .select({
      id: timetableEntries.id,
      userId: timetableEntries.userId,
      subjectId: timetableEntries.subjectId,
      subjectName: subjects.name,
      title: timetableEntries.title,
      dayOfWeek: timetableEntries.dayOfWeek,
      startTime: timetableEntries.startTime,
      endTime: timetableEntries.endTime,
      location: timetableEntries.location,
      color: timetableEntries.color,
      isRecurring: timetableEntries.isRecurring,
      createdAt: timetableEntries.createdAt,
    })
    .from(timetableEntries)
    .leftJoin(subjects, eq(timetableEntries.subjectId, subjects.id))
    .where(eq(timetableEntries.userId, userId));

  // Sort by day of week and then by start time
  return entries.sort((a, b) => {
    const dayDiff = dayOrder.indexOf(a.dayOfWeek) - dayOrder.indexOf(b.dayOfWeek);
    if (dayDiff !== 0) return dayDiff;
    return a.startTime.localeCompare(b.startTime);
  });
}

export async function getEntryById(id: number, userId: string) {
  const [entry] = await db
    .select({
      id: timetableEntries.id,
      userId: timetableEntries.userId,
      subjectId: timetableEntries.subjectId,
      subjectName: subjects.name,
      title: timetableEntries.title,
      dayOfWeek: timetableEntries.dayOfWeek,
      startTime: timetableEntries.startTime,
      endTime: timetableEntries.endTime,
      location: timetableEntries.location,
      color: timetableEntries.color,
      isRecurring: timetableEntries.isRecurring,
      createdAt: timetableEntries.createdAt,
    })
    .from(timetableEntries)
    .leftJoin(subjects, eq(timetableEntries.subjectId, subjects.id))
    .where(
      and(eq(timetableEntries.id, id), eq(timetableEntries.userId, userId))
    );

  return entry ?? null;
}

export async function createEntry(input: CreateEntryInput) {
  const [created] = await db
    .insert(timetableEntries)
    .values({
      userId: input.userId,
      subjectId: input.subjectId ?? null,
      title: input.title,
      dayOfWeek: input.dayOfWeek,
      startTime: input.startTime,
      endTime: input.endTime,
      location: input.location ?? null,
      color: input.color ?? null,
      isRecurring: input.isRecurring ?? true,
    })
    .returning();

  return created;
}

export async function updateEntry(
  id: number,
  userId: string,
  input: UpdateEntryInput
) {
  const updateData: Record<string, any> = {};

  if (input.subjectId !== undefined) updateData.subjectId = input.subjectId;
  if (input.title !== undefined) updateData.title = input.title;
  if (input.dayOfWeek !== undefined) updateData.dayOfWeek = input.dayOfWeek;
  if (input.startTime !== undefined) updateData.startTime = input.startTime;
  if (input.endTime !== undefined) updateData.endTime = input.endTime;
  if (input.location !== undefined) updateData.location = input.location;
  if (input.color !== undefined) updateData.color = input.color;
  if (input.isRecurring !== undefined) updateData.isRecurring = input.isRecurring;

  if (Object.keys(updateData).length === 0) {
    return getEntryById(id, userId);
  }

  const [updated] = await db
    .update(timetableEntries)
    .set(updateData)
    .where(
      and(eq(timetableEntries.id, id), eq(timetableEntries.userId, userId))
    )
    .returning();

  return updated ?? null;
}

export async function deleteEntry(id: number, userId: string) {
  const [deleted] = await db
    .delete(timetableEntries)
    .where(
      and(eq(timetableEntries.id, id), eq(timetableEntries.userId, userId))
    )
    .returning();

  return deleted ?? null;
}

export async function getEntriesByDay(userId: string, dayOfWeek: DayOfWeek) {
  const entries = await db
    .select({
      id: timetableEntries.id,
      subjectId: timetableEntries.subjectId,
      subjectName: subjects.name,
      title: timetableEntries.title,
      startTime: timetableEntries.startTime,
      endTime: timetableEntries.endTime,
      location: timetableEntries.location,
      color: timetableEntries.color,
    })
    .from(timetableEntries)
    .leftJoin(subjects, eq(timetableEntries.subjectId, subjects.id))
    .where(
      and(
        eq(timetableEntries.userId, userId),
        eq(timetableEntries.dayOfWeek, dayOfWeek)
      )
    )
    .orderBy(timetableEntries.startTime);

  return entries;
}
