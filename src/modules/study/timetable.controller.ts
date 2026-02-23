import { asyncHandler } from "../../core/middleware/async-handler.js";
import { parseNumber, parseUuid } from "../../shared/utils/parse.js";
import {
  listEntries,
  getEntryById,
  createEntry,
  updateEntry,
  deleteEntry,
  getEntriesByDay,
} from "./timetable.service.js";

export const listEntriesHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const entries = await listEntries(userId);
  res.json(entries);
});

export const getEntryHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const id = parseNumber(req.params.id as string);

  if (!id) {
    res.status(400).json({ message: "Invalid entry ID" });
    return;
  }

  const entry = await getEntryById(id, userId);
  if (!entry) {
    res.status(404).json({ message: "Timetable entry not found" });
    return;
  }

  res.json(entry);
});

export const createEntryHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const created = await createEntry({ ...req.body, userId });
  res.status(201).json(created);
});

export const updateEntryHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const id = parseNumber(req.params.id as string);

  if (!id) {
    res.status(400).json({ message: "Invalid entry ID" });
    return;
  }

  const existing = await getEntryById(id, userId);
  if (!existing) {
    res.status(404).json({ message: "Timetable entry not found" });
    return;
  }

  const updated = await updateEntry(id, userId, req.body);
  res.json(updated);
});

export const deleteEntryHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const id = parseNumber(req.params.id as string);

  if (!id) {
    res.status(400).json({ message: "Invalid entry ID" });
    return;
  }

  const existing = await getEntryById(id, userId);
  if (!existing) {
    res.status(404).json({ message: "Timetable entry not found" });
    return;
  }

  await deleteEntry(id, userId);
  res.json({ message: "Entry deleted" });
});

export const getStudentEntriesHandler = asyncHandler(async (req, res) => {
  const studentId = parseUuid(req.params.studentId as string);
  if (!studentId) {
    res.status(400).json({ message: "Valid studentId is required" });
    return;
  }
  const entries = await listEntries(studentId);
  res.json(entries);
});

export const getEntriesByDayHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const day = req.params.day as string;

  const validDays = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
  ];

  if (!validDays.includes(day)) {
    res.status(400).json({ message: "Invalid day of week" });
    return;
  }

  const entries = await getEntriesByDay(userId, day as any);
  res.json(entries);
});
