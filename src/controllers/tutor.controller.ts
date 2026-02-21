import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseUuid, parseNumber } from "../shared/utils/parse.js";
import {
  getTutorProfile,
  getTutorProfileById,
  createTutorProfile,
  updateTutorProfile,
  getTutorExpertise,
  addTutorExpertise,
  removeTutorExpertise,
  listTutorSessions,
  listStudentSessions,
  createTutoringSession,
  updateTutoringSession,
  getSessionById,
  addSessionFeedback,
  getSessionFeedback,
  getTutorStudents,
  getStudentTutors,
  createTutorStudentRelationship,
  listAvailableTutors,
  getTutorAnalytics,
} from "../services/tutor.service.js";

// ============ TUTOR PROFILE ============

export const getMyProfile = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  if (user.role !== "TUTOR") {
    res.status(403).json({ message: "Only tutors can access this endpoint" });
    return;
  }

  const profile = await getTutorProfile(user.id);
  if (!profile) {
    res.status(404).json({ message: "Tutor profile not found" });
    return;
  }

  const expertise = await getTutorExpertise(profile.id);
  res.json({ ...profile, expertise });
});

export const getProfile = asyncHandler(async (req: Request, res: Response) => {
  const tutorId = parseNumber(req.params.tutorId as string);
  if (!tutorId) {
    res.status(400).json({ message: "Invalid tutor ID" });
    return;
  }

  const profile = await getTutorProfileById(tutorId);
  if (!profile) {
    res.status(404).json({ message: "Tutor not found" });
    return;
  }

  const expertise = await getTutorExpertise(tutorId);
  res.json({ ...profile, expertise });
});

export const createProfile = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  if (user.role !== "TUTOR" && user.role !== "ADMIN") {
    res.status(403).json({ message: "Only tutors or admins can create tutor profiles" });
    return;
  }

  const { bio, qualifications, specializations, hourlyRate, availability } = req.body;

  const targetUserId = user.role === "ADMIN" && req.body.userId ? req.body.userId : user.id;

  const existing = await getTutorProfile(targetUserId);
  if (existing) {
    res.status(409).json({ message: "Tutor profile already exists" });
    return;
  }

  const profile = await createTutorProfile({
    userId: targetUserId,
    bio,
    qualifications,
    specializations,
    hourlyRate,
    availability,
  });

  res.status(201).json(profile);
});

export const updateProfile = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  if (user.role !== "TUTOR" && user.role !== "ADMIN") {
    res.status(403).json({ message: "Only tutors or admins can update tutor profiles" });
    return;
  }

  const { bio, qualifications, specializations, hourlyRate, availability, isActive } = req.body;

  const profile = await updateTutorProfile(user.id, {
    bio,
    qualifications,
    specializations,
    hourlyRate,
    availability,
    isActive,
  });

  if (!profile) {
    res.status(404).json({ message: "Tutor profile not found" });
    return;
  }

  res.json(profile);
});

// ============ TUTOR EXPERTISE ============

export const addExpertise = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  if (user.role !== "TUTOR" && user.role !== "ADMIN") {
    res.status(403).json({ message: "Only tutors or admins can add expertise" });
    return;
  }

  const profile = await getTutorProfile(user.id);
  if (!profile) {
    res.status(404).json({ message: "Tutor profile not found" });
    return;
  }

  const { subjectId, gradeMin, gradeMax, yearsExperience } = req.body;

  const expertise = await addTutorExpertise({
    tutorId: profile.id,
    subjectId,
    gradeMin,
    gradeMax,
    yearsExperience,
  });

  res.status(201).json(expertise);
});

export const removeExpertise = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  if (user.role !== "TUTOR" && user.role !== "ADMIN") {
    res.status(403).json({ message: "Only tutors or admins can remove expertise" });
    return;
  }

  const expertiseId = parseNumber(req.params.expertiseId as string);
  if (!expertiseId) {
    res.status(400).json({ message: "Invalid expertise ID" });
    return;
  }

  await removeTutorExpertise(expertiseId);
  res.json({ message: "Expertise removed" });
});

// ============ TUTORING SESSIONS ============

export const listMySessions = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const statusParam = req.query.status;
  const status = typeof statusParam === "string" ? statusParam.split(",") : undefined;
  const from = req.query.from ? new Date(req.query.from as string) : undefined;
  const to = req.query.to ? new Date(req.query.to as string) : undefined;
  const limit = parseNumber(req.query.limit as string | undefined) ?? undefined;

  if (user.role === "TUTOR") {
    const profile = await getTutorProfile(user.id);
    if (!profile) {
      res.status(404).json({ message: "Tutor profile not found" });
      return;
    }
    const sessions = await listTutorSessions(profile.id, { status, from, to, limit });
    res.json(sessions);
  } else if (user.role === "STUDENT") {
    const sessions = await listStudentSessions(user.id, { status, from, to, limit });
    res.json(sessions);
  } else {
    res.status(403).json({ message: "Invalid role for this endpoint" });
  }
});

export const createSession = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const {
    tutorId,
    studentId,
    title,
    description,
    scheduledStart,
    scheduledEnd,
    subjectId,
    moduleId,
    meetingLink,
    location,
  } = req.body;

  // Validate tutor ID
  let finalTutorId = tutorId;
  if (user.role === "TUTOR") {
    const profile = await getTutorProfile(user.id);
    if (!profile) {
      res.status(404).json({ message: "Tutor profile not found" });
      return;
    }
    finalTutorId = profile.id;
  }

  // Validate student ID
  let finalStudentId = studentId;
  if (user.role === "STUDENT") {
    finalStudentId = user.id;
  }

  if (!finalTutorId || !finalStudentId) {
    res.status(400).json({ message: "Tutor and student IDs are required" });
    return;
  }

  const session = await createTutoringSession({
    tutorId: finalTutorId,
    studentId: finalStudentId,
    title,
    description,
    scheduledStart: new Date(scheduledStart),
    scheduledEnd: new Date(scheduledEnd),
    subjectId,
    moduleId,
    meetingLink,
    location,
  });

  res.status(201).json(session);
});

export const updateSession = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const sessionId = parseNumber(req.params.sessionId as string);
  if (!sessionId) {
    res.status(400).json({ message: "Invalid session ID" });
    return;
  }

  const existingSession = await getSessionById(sessionId);
  if (!existingSession) {
    res.status(404).json({ message: "Session not found" });
    return;
  }

  // Check authorization
  if (user.role === "TUTOR") {
    const profile = await getTutorProfile(user.id);
    if (!profile || profile.id !== existingSession.tutorId) {
      res.status(403).json({ message: "Not authorized to update this session" });
      return;
    }
  } else if (user.role === "STUDENT") {
    if (existingSession.studentId !== user.id) {
      res.status(403).json({ message: "Not authorized to update this session" });
      return;
    }
  } else if (user.role !== "ADMIN") {
    res.status(403).json({ message: "Not authorized" });
    return;
  }

  const {
    title,
    description,
    scheduledStart,
    scheduledEnd,
    actualStart,
    actualEnd,
    status,
    meetingLink,
    location,
    notes,
  } = req.body;

  const session = await updateTutoringSession(sessionId, {
    title,
    description,
    scheduledStart: scheduledStart ? new Date(scheduledStart) : undefined,
    scheduledEnd: scheduledEnd ? new Date(scheduledEnd) : undefined,
    actualStart: actualStart ? new Date(actualStart) : undefined,
    actualEnd: actualEnd ? new Date(actualEnd) : undefined,
    status,
    meetingLink,
    location,
    notes,
  });

  res.json(session);
});

// ============ SESSION FEEDBACK ============

export const submitFeedback = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const sessionId = parseNumber(req.params.sessionId as string);
  if (!sessionId) {
    res.status(400).json({ message: "Invalid session ID" });
    return;
  }

  const existingSession = await getSessionById(sessionId);
  if (!existingSession) {
    res.status(404).json({ message: "Session not found" });
    return;
  }

  // Check that user was part of the session
  const profile = user.role === "TUTOR" ? await getTutorProfile(user.id) : null;
  const isParticipant =
    existingSession.studentId === user.id ||
    (profile && profile.id === existingSession.tutorId);

  if (!isParticipant) {
    res.status(403).json({ message: "Only session participants can submit feedback" });
    return;
  }

  const { rating, comment, isPublic } = req.body;

  // Determine who the feedback is for
  let toUserId: string;
  if (user.role === "STUDENT") {
    // Student giving feedback to tutor
    const tutorProfile = await getTutorProfileById(existingSession.tutorId);
    if (!tutorProfile) {
      res.status(404).json({ message: "Tutor not found" });
      return;
    }
    toUserId = tutorProfile.userId;
  } else {
    // Tutor giving feedback to student
    toUserId = existingSession.studentId;
  }

  const feedback = await addSessionFeedback({
    sessionId,
    fromUserId: user.id,
    toUserId,
    rating,
    comment,
    isPublic,
  });

  res.status(201).json(feedback);
});

export const getFeedback = asyncHandler(async (req: Request, res: Response) => {
  const sessionId = parseNumber(req.params.sessionId as string);
  if (!sessionId) {
    res.status(400).json({ message: "Invalid session ID" });
    return;
  }

  const feedback = await getSessionFeedback(sessionId);
  res.json(feedback);
});

// ============ TUTOR-STUDENT RELATIONSHIPS ============

export const getMyStudents = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  if (user.role !== "TUTOR") {
    res.status(403).json({ message: "Only tutors can access this endpoint" });
    return;
  }

  const profile = await getTutorProfile(user.id);
  if (!profile) {
    res.status(404).json({ message: "Tutor profile not found" });
    return;
  }

  const students = await getTutorStudents(profile.id);
  res.json(students);
});

export const getMyTutors = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  if (user.role !== "STUDENT") {
    res.status(403).json({ message: "Only students can access this endpoint" });
    return;
  }

  const tutors = await getStudentTutors(user.id);
  res.json(tutors);
});

export const connectWithStudent = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  if (user.role !== "TUTOR" && user.role !== "ADMIN") {
    res.status(403).json({ message: "Only tutors or admins can create relationships" });
    return;
  }

  const { studentId, notes } = req.body;

  let tutorId: number;
  if (user.role === "TUTOR") {
    const profile = await getTutorProfile(user.id);
    if (!profile) {
      res.status(404).json({ message: "Tutor profile not found" });
      return;
    }
    tutorId = profile.id;
  } else {
    tutorId = req.body.tutorId;
    if (!tutorId) {
      res.status(400).json({ message: "Tutor ID required for admin" });
      return;
    }
  }

  const relationship = await createTutorStudentRelationship({
    tutorId,
    studentId,
    notes,
  });

  res.status(201).json(relationship);
});

// ============ TUTOR DISCOVERY ============

export const discoverTutors = asyncHandler(async (req: Request, res: Response) => {
  const subjectId = parseNumber(req.query.subjectId as string | undefined) ?? undefined;
  const grade = parseNumber(req.query.grade as string | undefined) ?? undefined;
  const limit = parseNumber(req.query.limit as string | undefined) ?? undefined;

  const tutors = await listAvailableTutors({ subjectId, grade, limit });
  res.json(tutors);
});

// ============ TUTOR ANALYTICS ============

export const getAnalytics = asyncHandler(async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  if (user.role !== "TUTOR" && user.role !== "ADMIN") {
    res.status(403).json({ message: "Only tutors or admins can view analytics" });
    return;
  }

  let tutorId: number;
  if (user.role === "TUTOR") {
    const profile = await getTutorProfile(user.id);
    if (!profile) {
      res.status(404).json({ message: "Tutor profile not found" });
      return;
    }
    tutorId = profile.id;
  } else {
    const id = parseNumber(req.query.tutorId as string | undefined);
    if (!id) {
      res.status(400).json({ message: "Tutor ID required for admin" });
      return;
    }
    tutorId = id;
  }

  const analytics = await getTutorAnalytics(tutorId);
  res.json(analytics);
});
