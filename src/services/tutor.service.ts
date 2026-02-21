import { eq, and, gte, lte, desc, sql, inArray } from "drizzle-orm";
import { db } from "../core/database/index.js";
import {
  tutorProfiles,
  tutorSubjectExpertise,
  tutoringSessions,
  sessionFeedback,
  tutorStudentRelationships,
  users,
  subjects,
  modules,
  roles,
} from "../core/database/schema/index.js";

// ============ TUTOR PROFILE ============

export async function getTutorProfile(userId: string) {
  const [profile] = await db
    .select({
      id: tutorProfiles.id,
      userId: tutorProfiles.userId,
      bio: tutorProfiles.bio,
      qualifications: tutorProfiles.qualifications,
      specializations: tutorProfiles.specializations,
      hourlyRate: tutorProfiles.hourlyRate,
      availability: tutorProfiles.availability,
      rating: tutorProfiles.rating,
      totalSessions: tutorProfiles.totalSessions,
      isActive: tutorProfiles.isActive,
      createdAt: tutorProfiles.createdAt,
      userName: users.name,
      userEmail: users.email,
      userImage: users.image,
    })
    .from(tutorProfiles)
    .innerJoin(users, eq(tutorProfiles.userId, users.id))
    .where(eq(tutorProfiles.userId, userId))
    .limit(1);

  return profile ?? null;
}

export async function getTutorProfileById(tutorId: number) {
  const [profile] = await db
    .select({
      id: tutorProfiles.id,
      userId: tutorProfiles.userId,
      bio: tutorProfiles.bio,
      qualifications: tutorProfiles.qualifications,
      specializations: tutorProfiles.specializations,
      hourlyRate: tutorProfiles.hourlyRate,
      availability: tutorProfiles.availability,
      rating: tutorProfiles.rating,
      totalSessions: tutorProfiles.totalSessions,
      isActive: tutorProfiles.isActive,
      userName: users.name,
      userEmail: users.email,
      userImage: users.image,
    })
    .from(tutorProfiles)
    .innerJoin(users, eq(tutorProfiles.userId, users.id))
    .where(eq(tutorProfiles.id, tutorId))
    .limit(1);

  return profile ?? null;
}

export async function createTutorProfile(data: {
  userId: string;
  bio?: string;
  qualifications?: string[];
  specializations?: string[];
  hourlyRate?: number;
  availability?: Record<string, { start: string; end: string }[]>;
}) {
  const [profile] = await db
    .insert(tutorProfiles)
    .values({
      userId: data.userId,
      bio: data.bio ?? null,
      qualifications: data.qualifications ?? [],
      specializations: data.specializations ?? [],
      hourlyRate: data.hourlyRate ?? null,
      availability: data.availability ?? {},
    })
    .returning();

  return profile;
}

export async function updateTutorProfile(
  userId: string,
  data: Partial<{
    bio: string;
    qualifications: string[];
    specializations: string[];
    hourlyRate: number;
    availability: Record<string, { start: string; end: string }[]>;
    isActive: boolean;
  }>
) {
  const [profile] = await db
    .update(tutorProfiles)
    .set({
      ...data,
      updatedAt: new Date(),
    })
    .where(eq(tutorProfiles.userId, userId))
    .returning();

  return profile;
}

// ============ TUTOR EXPERTISE ============

export async function getTutorExpertise(tutorId: number) {
  return db
    .select({
      id: tutorSubjectExpertise.id,
      subjectId: tutorSubjectExpertise.subjectId,
      subjectName: subjects.name,
      gradeMin: tutorSubjectExpertise.gradeMin,
      gradeMax: tutorSubjectExpertise.gradeMax,
      yearsExperience: tutorSubjectExpertise.yearsExperience,
    })
    .from(tutorSubjectExpertise)
    .innerJoin(subjects, eq(tutorSubjectExpertise.subjectId, subjects.id))
    .where(eq(tutorSubjectExpertise.tutorId, tutorId));
}

export async function addTutorExpertise(data: {
  tutorId: number;
  subjectId: number;
  gradeMin: number;
  gradeMax: number;
  yearsExperience?: number;
}) {
  const [expertise] = await db
    .insert(tutorSubjectExpertise)
    .values({
      tutorId: data.tutorId,
      subjectId: data.subjectId,
      gradeMin: data.gradeMin,
      gradeMax: data.gradeMax,
      yearsExperience: data.yearsExperience ?? 0,
    })
    .returning();

  return expertise;
}

export async function removeTutorExpertise(expertiseId: number) {
  await db.delete(tutorSubjectExpertise).where(eq(tutorSubjectExpertise.id, expertiseId));
}

// ============ TUTORING SESSIONS ============

export async function listTutorSessions(tutorId: number, options?: {
  status?: string[];
  from?: Date;
  to?: Date;
  limit?: number;
}) {
  let query = db
    .select({
      id: tutoringSessions.id,
      title: tutoringSessions.title,
      description: tutoringSessions.description,
      scheduledStart: tutoringSessions.scheduledStart,
      scheduledEnd: tutoringSessions.scheduledEnd,
      actualStart: tutoringSessions.actualStart,
      actualEnd: tutoringSessions.actualEnd,
      status: tutoringSessions.status,
      meetingLink: tutoringSessions.meetingLink,
      location: tutoringSessions.location,
      notes: tutoringSessions.notes,
      studentId: tutoringSessions.studentId,
      studentName: users.name,
      subjectId: tutoringSessions.subjectId,
      subjectName: subjects.name,
      moduleId: tutoringSessions.moduleId,
      moduleTitle: modules.title,
    })
    .from(tutoringSessions)
    .innerJoin(users, eq(tutoringSessions.studentId, users.id))
    .leftJoin(subjects, eq(tutoringSessions.subjectId, subjects.id))
    .leftJoin(modules, eq(tutoringSessions.moduleId, modules.id))
    .where(eq(tutoringSessions.tutorId, tutorId))
    .orderBy(desc(tutoringSessions.scheduledStart))
    .$dynamic();

  if (options?.from) {
    query = query.where(gte(tutoringSessions.scheduledStart, options.from));
  }
  if (options?.to) {
    query = query.where(lte(tutoringSessions.scheduledStart, options.to));
  }
  if (options?.status && options.status.length > 0) {
    query = query.where(
      inArray(tutoringSessions.status, options.status as ("scheduled" | "in_progress" | "completed" | "cancelled" | "no_show")[])
    );
  }

  const results = await query.limit(options?.limit ?? 50);
  return results;
}

export async function listStudentSessions(studentId: string, options?: {
  status?: string[];
  from?: Date;
  to?: Date;
  limit?: number;
}) {
  let query = db
    .select({
      id: tutoringSessions.id,
      title: tutoringSessions.title,
      description: tutoringSessions.description,
      scheduledStart: tutoringSessions.scheduledStart,
      scheduledEnd: tutoringSessions.scheduledEnd,
      actualStart: tutoringSessions.actualStart,
      actualEnd: tutoringSessions.actualEnd,
      status: tutoringSessions.status,
      meetingLink: tutoringSessions.meetingLink,
      location: tutoringSessions.location,
      notes: tutoringSessions.notes,
      tutorId: tutoringSessions.tutorId,
      tutorName: users.name,
      subjectId: tutoringSessions.subjectId,
      subjectName: subjects.name,
      moduleId: tutoringSessions.moduleId,
      moduleTitle: modules.title,
    })
    .from(tutoringSessions)
    .innerJoin(tutorProfiles, eq(tutoringSessions.tutorId, tutorProfiles.id))
    .innerJoin(users, eq(tutorProfiles.userId, users.id))
    .leftJoin(subjects, eq(tutoringSessions.subjectId, subjects.id))
    .leftJoin(modules, eq(tutoringSessions.moduleId, modules.id))
    .where(eq(tutoringSessions.studentId, studentId))
    .orderBy(desc(tutoringSessions.scheduledStart))
    .$dynamic();

  if (options?.from) {
    query = query.where(gte(tutoringSessions.scheduledStart, options.from));
  }
  if (options?.to) {
    query = query.where(lte(tutoringSessions.scheduledStart, options.to));
  }
  if (options?.status && options.status.length > 0) {
    query = query.where(
      inArray(tutoringSessions.status, options.status as ("scheduled" | "in_progress" | "completed" | "cancelled" | "no_show")[])
    );
  }

  const results = await query.limit(options?.limit ?? 50);
  return results;
}

export async function createTutoringSession(data: {
  tutorId: number;
  studentId: string;
  title: string;
  description?: string;
  scheduledStart: Date;
  scheduledEnd: Date;
  subjectId?: number;
  moduleId?: number;
  meetingLink?: string;
  location?: string;
}) {
  const [session] = await db
    .insert(tutoringSessions)
    .values({
      tutorId: data.tutorId,
      studentId: data.studentId,
      title: data.title,
      description: data.description ?? null,
      scheduledStart: data.scheduledStart,
      scheduledEnd: data.scheduledEnd,
      subjectId: data.subjectId ?? null,
      moduleId: data.moduleId ?? null,
      meetingLink: data.meetingLink ?? null,
      location: data.location ?? null,
    })
    .returning();

  return session;
}

export async function updateTutoringSession(
  sessionId: number,
  data: Partial<{
    title: string;
    description: string;
    scheduledStart: Date;
    scheduledEnd: Date;
    actualStart: Date;
    actualEnd: Date;
    status: "scheduled" | "in_progress" | "completed" | "cancelled" | "no_show";
    meetingLink: string;
    location: string;
    notes: string;
  }>
) {
  const [session] = await db
    .update(tutoringSessions)
    .set({
      ...data,
      updatedAt: new Date(),
    })
    .where(eq(tutoringSessions.id, sessionId))
    .returning();

  return session;
}

export async function getSessionById(sessionId: number) {
  const [session] = await db
    .select()
    .from(tutoringSessions)
    .where(eq(tutoringSessions.id, sessionId))
    .limit(1);

  return session ?? null;
}

// ============ SESSION FEEDBACK ============

export async function addSessionFeedback(data: {
  sessionId: number;
  fromUserId: string;
  toUserId: string;
  rating: number;
  comment?: string;
  isPublic?: boolean;
}) {
  const [feedback] = await db
    .insert(sessionFeedback)
    .values({
      sessionId: data.sessionId,
      fromUserId: data.fromUserId,
      toUserId: data.toUserId,
      rating: data.rating,
      comment: data.comment ?? null,
      isPublic: data.isPublic ?? false,
    })
    .returning();

  // Update tutor rating if feedback is for a tutor
  const [tutorProfile] = await db
    .select({ id: tutorProfiles.id })
    .from(tutorProfiles)
    .where(eq(tutorProfiles.userId, data.toUserId))
    .limit(1);

  if (tutorProfile) {
    // Calculate new average rating
    const allFeedback = await db
      .select({ rating: sessionFeedback.rating })
      .from(sessionFeedback)
      .where(eq(sessionFeedback.toUserId, data.toUserId));

    const avgRating = Math.round(
      (allFeedback.reduce((sum, f) => sum + f.rating, 0) / allFeedback.length) * 100
    );

    await db
      .update(tutorProfiles)
      .set({ rating: avgRating, updatedAt: new Date() })
      .where(eq(tutorProfiles.id, tutorProfile.id));
  }

  return feedback;
}

export async function getSessionFeedback(sessionId: number) {
  return db
    .select({
      id: sessionFeedback.id,
      rating: sessionFeedback.rating,
      comment: sessionFeedback.comment,
      isPublic: sessionFeedback.isPublic,
      fromUserId: sessionFeedback.fromUserId,
      fromUserName: users.name,
      createdAt: sessionFeedback.createdAt,
    })
    .from(sessionFeedback)
    .innerJoin(users, eq(sessionFeedback.fromUserId, users.id))
    .where(eq(sessionFeedback.sessionId, sessionId));
}

// ============ TUTOR-STUDENT RELATIONSHIPS ============

export async function getTutorStudents(tutorId: number) {
  return db
    .select({
      id: tutorStudentRelationships.id,
      studentId: tutorStudentRelationships.studentId,
      studentName: users.name,
      studentEmail: users.email,
      status: tutorStudentRelationships.status,
      startedAt: tutorStudentRelationships.startedAt,
      notes: tutorStudentRelationships.notes,
    })
    .from(tutorStudentRelationships)
    .innerJoin(users, eq(tutorStudentRelationships.studentId, users.id))
    .where(eq(tutorStudentRelationships.tutorId, tutorId));
}

export async function getStudentTutors(studentId: string) {
  return db
    .select({
      id: tutorStudentRelationships.id,
      tutorId: tutorStudentRelationships.tutorId,
      tutorName: users.name,
      tutorEmail: users.email,
      tutorImage: users.image,
      rating: tutorProfiles.rating,
      status: tutorStudentRelationships.status,
      startedAt: tutorStudentRelationships.startedAt,
    })
    .from(tutorStudentRelationships)
    .innerJoin(tutorProfiles, eq(tutorStudentRelationships.tutorId, tutorProfiles.id))
    .innerJoin(users, eq(tutorProfiles.userId, users.id))
    .where(eq(tutorStudentRelationships.studentId, studentId));
}

export async function createTutorStudentRelationship(data: {
  tutorId: number;
  studentId: string;
  notes?: string;
}) {
  const [relationship] = await db
    .insert(tutorStudentRelationships)
    .values({
      tutorId: data.tutorId,
      studentId: data.studentId,
      notes: data.notes ?? null,
    })
    .returning();

  return relationship;
}

// ============ TUTOR DISCOVERY ============

export async function listAvailableTutors(options?: {
  subjectId?: number;
  grade?: number;
  limit?: number;
}) {
  let query = db
    .select({
      id: tutorProfiles.id,
      userId: tutorProfiles.userId,
      name: users.name,
      image: users.image,
      bio: tutorProfiles.bio,
      specializations: tutorProfiles.specializations,
      hourlyRate: tutorProfiles.hourlyRate,
      rating: tutorProfiles.rating,
      totalSessions: tutorProfiles.totalSessions,
    })
    .from(tutorProfiles)
    .innerJoin(users, eq(tutorProfiles.userId, users.id))
    .where(eq(tutorProfiles.isActive, true))
    .orderBy(desc(tutorProfiles.rating))
    .$dynamic();

  const results = await query.limit(options?.limit ?? 20);
  return results;
}

// ============ TUTOR ANALYTICS ============

export async function getTutorAnalytics(tutorId: number) {
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  // Total sessions
  const [totalStats] = await db
    .select({
      total: sql<number>`count(*)::int`,
      completed: sql<number>`count(*) filter (where ${tutoringSessions.status} = 'completed')::int`,
      cancelled: sql<number>`count(*) filter (where ${tutoringSessions.status} = 'cancelled')::int`,
    })
    .from(tutoringSessions)
    .where(eq(tutoringSessions.tutorId, tutorId));

  // Last 30 days
  const [last30Days] = await db
    .select({
      sessions: sql<number>`count(*)::int`,
      completed: sql<number>`count(*) filter (where ${tutoringSessions.status} = 'completed')::int`,
    })
    .from(tutoringSessions)
    .where(
      and(
        eq(tutoringSessions.tutorId, tutorId),
        gte(tutoringSessions.scheduledStart, thirtyDaysAgo)
      )
    );

  // Upcoming sessions
  const [upcoming] = await db
    .select({
      count: sql<number>`count(*)::int`,
    })
    .from(tutoringSessions)
    .where(
      and(
        eq(tutoringSessions.tutorId, tutorId),
        eq(tutoringSessions.status, "scheduled"),
        gte(tutoringSessions.scheduledStart, now)
      )
    );

  // Unique students
  const [students] = await db
    .select({
      count: sql<number>`count(distinct ${tutorStudentRelationships.studentId})::int`,
    })
    .from(tutorStudentRelationships)
    .where(
      and(
        eq(tutorStudentRelationships.tutorId, tutorId),
        eq(tutorStudentRelationships.status, "active")
      )
    );

  return {
    totalSessions: totalStats?.total ?? 0,
    completedSessions: totalStats?.completed ?? 0,
    cancelledSessions: totalStats?.cancelled ?? 0,
    last30DaysSessions: last30Days?.sessions ?? 0,
    last30DaysCompleted: last30Days?.completed ?? 0,
    upcomingSessions: upcoming?.count ?? 0,
    activeStudents: students?.count ?? 0,
  };
}
