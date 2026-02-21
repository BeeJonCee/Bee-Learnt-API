/**
 * Progress Tracking Controller
 * 
 * Provides progress tracking and analytics:
 * - Student progress summary
 * - Parent dashboard (children's progress)
 * - Module completion tracking
 * - Quiz performance analytics
 * - Time spent tracking
 */

import type { Request, Response } from "express";
import { eq, and, inArray } from "drizzle-orm";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { getProgressSummary, listProgress, upsertProgress } from "../services/progress.service.js";
import { progressQuerySchema, progressUpdateSchema } from "../shared/validators/index.js";
import { db } from "../core/database/index.js";
import {
  progressTracking,
  quizAttempts,
  moduleAssignments,
  studySessions,
  users,
  quizzes,
} from "../core/database/schema/index.js";
import { getAccessibleStudentIds } from "../lib/rbac/guard.js";

// ============ EXISTING ENDPOINTS (PRESERVED) ============

export const summary = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  const data = await getProgressSummary(userId);
  res.json(data);
});

export const list = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const qLessonId = req.query.lessonId as string | undefined;
  const qModuleId = req.query.moduleId as string | undefined;
  const parsed = progressQuerySchema.safeParse({
    lessonId: qLessonId ? Number(qLessonId) : undefined,
    moduleId: qModuleId ? Number(qModuleId) : undefined,
  });

  if (!parsed.success) {
    res.status(400).json({ message: "Invalid query", issues: parsed.error.issues });
    return;
  }

  const data = await listProgress(userId, parsed.data);
  res.json(data);
});

export const update = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const parsed = progressUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ message: "Invalid payload", issues: parsed.error.issues });
    return;
  }

  if (!parsed.data.lessonId && !parsed.data.moduleId) {
    res.status(400).json({ message: "lessonId or moduleId is required" });
    return;
  }

  const result = await upsertProgress(userId, parsed.data);
  res.status(result.created ? 201 : 200).json(result.record);
});

// ============ NEW RBAC-ENABLED ENDPOINTS ============

/**
 * GET /api/students/:studentId/progress
 * Get comprehensive progress summary for a student
 * Role: STUDENT (self), PARENT (linked), TUTOR, ADMIN
 */
export const getStudentProgress = asyncHandler(async (req: Request, res: Response) => {
  const studentId = req.params.studentId as string;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  // Check access
  const accessibleIds = await getAccessibleStudentIds(req.user.id, req.user.role);
  if (!accessibleIds.includes(studentId)) {
    res.status(403).json({ error: "Access denied" });
    return;
  }

  // Get module assignments with completion status
  const assignments = await db.query.moduleAssignments.findMany({
    where: eq(moduleAssignments.studentId, studentId),
    with: {
      module: {
        with: {
          subject: true,
        },
      },
    },
  });

  // Get lesson completion stats
  const lessonProgress = await db.query.progressTracking.findMany({
    where: and(
      eq(progressTracking.userId, studentId),
      eq(progressTracking.completed, true)
    ),
  });

  // Get quiz attempts
  const attempts = await db.query.quizAttempts.findMany({
    where: eq(quizAttempts.userId, studentId),
    with: {
      quiz: {
        with: {
          module: true,
        },
      },
    },
    orderBy: (attempts, { desc }) => [desc(attempts.createdAt)],
  });

  // Get study time
  const sessions = await db.query.studySessions.findMany({
    where: eq(studySessions.userId, studentId),
  });

  const totalStudyMinutes = sessions.reduce((sum, session) => sum + session.durationMinutes, 0);

  // Calculate statistics
  const totalAssignments = assignments.length;
  const completedAssignments = assignments.filter((a) => a.status === "completed").length;
  const inProgressAssignments = assignments.filter((a) => a.status === "in_progress").length;
  const pendingAssignments = assignments.filter((a) => a.status === "assigned").length;

  const completedLessons = lessonProgress.length;
  const totalTimeSpent = lessonProgress.reduce((sum, p) => sum + p.timeSpentMinutes, 0);

  const totalQuizAttempts = attempts.length;
  const averageQuizScore =
    attempts.length > 0
      ? attempts.reduce((sum, a) => sum + (a.score / a.maxScore) * 100, 0) / attempts.length
      : 0;

  // Module-wise progress
  const moduleProgress = assignments.map((assignment) => {
    const moduleAttempts = attempts.filter((a) => a.quiz.moduleId === assignment.moduleId);
    const avgScore =
      moduleAttempts.length > 0
        ? moduleAttempts.reduce((sum, a) => sum + (a.score / a.maxScore) * 100, 0) /
          moduleAttempts.length
        : 0;

    return {
      moduleId: assignment.moduleId,
      moduleName: assignment.module.title,
      subjectName: assignment.module.subject.name,
      grade: assignment.module.grade,
      status: assignment.status,
      assignedAt: assignment.assignedAt,
      unlockedAt: assignment.unlockedAt,
      completedAt: assignment.completedAt,
      dueDate: assignment.dueDate,
      quizAttempts: moduleAttempts.length,
      averageScore: Math.round(avgScore),
    };
  });

  res.json({
    studentId,
    summary: {
      totalAssignments,
      completedAssignments,
      inProgressAssignments,
      pendingAssignments,
      completionRate: totalAssignments > 0 ? Math.round((completedAssignments / totalAssignments) * 100) : 0,
      completedLessons,
      totalTimeSpent: totalTimeSpent + totalStudyMinutes,
      totalQuizAttempts,
      averageQuizScore: Math.round(averageQuizScore),
    },
    moduleProgress,
    recentActivity: attempts.slice(0, 10).map((a) => ({
      type: "quiz_attempt",
      quizTitle: a.quiz.title,
      moduleName: a.quiz.module.title,
      score: a.score,
      maxScore: a.maxScore,
      percentage: Math.round((a.score / a.maxScore) * 100),
      createdAt: a.createdAt,
    })),
  });
});

/**
 * GET /api/parents/dashboard
 * Get dashboard with all linked children's progress
 * Role: PARENT
 */
export const getParentDashboard = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  if (req.user.role !== "PARENT") {
    res.status(403).json({ error: "Only parents can access this endpoint" });
    return;
  }

  // Get all linked students
  const studentIds = await getAccessibleStudentIds(req.user.id, req.user.role);

  if (studentIds.length === 0) {
    res.json({
      message: "No students linked",
      students: [],
      summary: {
        totalStudents: 0,
        totalAssignments: 0,
        completedAssignments: 0,
        averageProgress: 0,
      },
    });
    return;
  }

  // Get students with their progress
  const studentsData = await Promise.all(
    studentIds.map(async (studentId) => {
      const student = await db.query.users.findFirst({
        where: eq(users.id, studentId),
        with: {
          studentProfile: true,
        },
      });

      if (!student) return null;

      // Get assignments
      const assignments = await db.query.moduleAssignments.findMany({
        where: eq(moduleAssignments.studentId, studentId),
      });

      // Get recent quiz attempts
      const attempts = await db.query.quizAttempts.findMany({
        where: eq(quizAttempts.userId, studentId),
        orderBy: (attempts, { desc }) => [desc(attempts.createdAt)],
        limit: 5,
      });

      const completedCount = assignments.filter((a) => a.status === "completed").length;
      const avgScore =
        attempts.length > 0
          ? attempts.reduce((sum, a) => sum + (a.score / a.maxScore) * 100, 0) / attempts.length
          : 0;

      return {
        id: student.id,
        name: student.name,
        grade: student.studentProfile?.grade,
        school: student.studentProfile?.school,
        totalAssignments: assignments.length,
        completedAssignments: completedCount,
        progressPercentage:
          assignments.length > 0 ? Math.round((completedCount / assignments.length) * 100) : 0,
        recentQuizAverage: Math.round(avgScore),
        lastActivity: attempts[0]?.createdAt || null,
      };
    })
  );

  const students = studentsData.filter(Boolean);

  // Calculate summary
  const totalAssignments = students.reduce((sum, s) => sum + (s?.totalAssignments || 0), 0);
  const completedAssignments = students.reduce((sum, s) => sum + (s?.completedAssignments || 0), 0);
  const averageProgress =
    students.length > 0
      ? Math.round(
          students.reduce((sum, s) => sum + (s?.progressPercentage || 0), 0) / students.length
        )
      : 0;

  res.json({
    students,
    summary: {
      totalStudents: students.length,
      totalAssignments,
      completedAssignments,
      averageProgress,
    },
  });
});

/**
 * GET /api/students/:studentId/modules/:moduleId/progress
 * Get detailed progress for a specific module
 * Role: STUDENT (self), PARENT (linked), TUTOR, ADMIN
 */
export const getModuleProgress = asyncHandler(async (req: Request, res: Response) => {
  const studentId = req.params.studentId as string;
  const moduleId = req.params.moduleId as string;

  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  // Check access
  const accessibleIds = await getAccessibleStudentIds(req.user.id, req.user.role);
  if (!accessibleIds.includes(studentId)) {
    res.status(403).json({ error: "Access denied" });
    return;
  }

  // Get module assignment
  const assignment = await db.query.moduleAssignments.findFirst({
    where: and(
      eq(moduleAssignments.studentId, studentId),
      eq(moduleAssignments.moduleId, parseInt(moduleId, 10))
    ),
    with: {
      module: {
        with: {
          subject: true,
          lessons: true,
        },
      },
    },
  });

  if (!assignment) {
    res.status(404).json({ error: "Module not assigned to this student" });
    return;
  }

  // Get lesson progress
  const lessonIds = assignment.module.lessons.map((l) => l.id);
  const lessonProgress = await db.query.progressTracking.findMany({
    where: and(
      eq(progressTracking.userId, studentId),
      inArray(progressTracking.lessonId, lessonIds)
    ),
  });

  // Get quiz attempts for this module
  const moduleQuizzes = await db.query.quizzes.findMany({
    where: eq(quizzes.moduleId, parseInt(moduleId, 10)),
  });

  const quizIds = moduleQuizzes.map((q) => q.id);
  const attempts = await db.query.quizAttempts.findMany({
    where: and(
      eq(quizAttempts.userId, studentId),
      inArray(quizAttempts.quizId, quizIds)
    ),
    with: {
      quiz: true,
    },
    orderBy: (attempts, { desc }) => [desc(attempts.createdAt)],
  });

  // Calculate statistics
  const totalLessons = assignment.module.lessons.length;
  const completedLessons = lessonProgress.filter((p) => p.completed).length;
  const totalTimeSpent = lessonProgress.reduce((sum, p) => sum + p.timeSpentMinutes, 0);

  const avgQuizScore =
    attempts.length > 0
      ? attempts.reduce((sum, a) => sum + (a.score / a.maxScore) * 100, 0) / attempts.length
      : 0;

  res.json({
    module: {
      id: assignment.module.id,
      title: assignment.module.title,
      description: assignment.module.description,
      subjectName: assignment.module.subject.name,
      grade: assignment.module.grade,
    },
    assignment: {
      status: assignment.status,
      assignedAt: assignment.assignedAt,
      unlockedAt: assignment.unlockedAt,
      completedAt: assignment.completedAt,
      dueDate: assignment.dueDate,
    },
    progress: {
      totalLessons,
      completedLessons,
      completionPercentage: totalLessons > 0 ? Math.round((completedLessons / totalLessons) * 100) : 0,
      totalTimeSpent,
      quizAttempts: attempts.length,
      averageQuizScore: Math.round(avgQuizScore),
    },
    lessons: assignment.module.lessons.map((lesson) => {
      const progress = lessonProgress.find((p) => p.lessonId === lesson.id);
      return {
        id: lesson.id,
        title: lesson.title,
        order: lesson.order,
        completed: progress?.completed || false,
        timeSpent: progress?.timeSpentMinutes || 0,
        lastAccessed: progress?.lastAccessedAt || null,
      };
    }),
    quizzes: moduleQuizzes.map((quiz) => {
      const quizAttempts = attempts.filter((a) => a.quizId === quiz.id);
      const bestAttempt = quizAttempts.reduce(
        (best, current) =>
          !best || (current.score / current.maxScore) > (best.score / best.maxScore)
            ? current
            : best,
        null as typeof attempts[0] | null
      );

      return {
        id: quiz.id,
        title: quiz.title,
        difficulty: quiz.difficulty,
        attempts: quizAttempts.length,
        bestScore: bestAttempt ? Math.round((bestAttempt.score / bestAttempt.maxScore) * 100) : null,
        lastAttempt: quizAttempts[0]?.createdAt || null,
      };
    }),
  });
});

// ============ TOPIC MASTERY ANALYTICS ============

import { masteryService } from "../services/mastery.service.js";

/**
 * GET /api/progress/mastery
 * Get authenticated user's topic mastery breakdown
 * Role: STUDENT (self), PARENT (linked), TUTOR, ADMIN
 */
export const getUserMastery = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const subjectId = req.query.subjectId ? parseInt(req.query.subjectId as string, 10) : undefined;
  const userId = req.query.userId as string || req.user.id;

  // If requesting another user's mastery, check access
  if (userId !== req.user.id) {
    const accessibleIds = await getAccessibleStudentIds(req.user.id, req.user.role);
    if (!accessibleIds.includes(userId) && req.user.role !== "ADMIN" && req.user.role !== "TUTOR") {
      res.status(403).json({ error: "Access denied" });
      return;
    }
  }

  const mastery = await masteryService.getUserMastery(userId, subjectId);
  res.json({ userId, mastery });
});

/**
 * GET /api/progress/mastery/weak
 * Get authenticated user's weakest topics
 * Role: STUDENT (self), PARENT (linked), TUTOR, ADMIN
 */
export const getWeakTopics = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const userId = req.query.userId as string || req.user.id;
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 5;
  const minQuestions = req.query.minQuestions ? parseInt(req.query.minQuestions as string, 10) : 3;

  // If requesting another user's mastery, check access
  if (userId !== req.user.id) {
    const accessibleIds = await getAccessibleStudentIds(req.user.id, req.user.role);
    if (!accessibleIds.includes(userId) && req.user.role !== "ADMIN" && req.user.role !== "TUTOR") {
      res.status(403).json({ error: "Access denied" });
      return;
    }
  }

  const weakTopics = await masteryService.getWeakestTopics(userId, limit, minQuestions);
  res.json({ userId, weakTopics });
});

/**
 * GET /api/progress/mastery/strong
 * Get authenticated user's strongest topics
 * Role: STUDENT (self), PARENT (linked), TUTOR, ADMIN
 */
export const getStrongTopics = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const userId = req.query.userId as string || req.user.id;
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 5;
  const minQuestions = req.query.minQuestions ? parseInt(req.query.minQuestions as string, 10) : 3;

  // If requesting another user's mastery, check access
  if (userId !== req.user.id) {
    const accessibleIds = await getAccessibleStudentIds(req.user.id, req.user.role);
    if (!accessibleIds.includes(userId) && req.user.role !== "ADMIN" && req.user.role !== "TUTOR") {
      res.status(403).json({ error: "Access denied" });
      return;
    }
  }

  const strongTopics = await masteryService.getStrongestTopics(userId, limit, minQuestions);
  res.json({ userId, strongTopics });
});

/**
 * GET /api/progress/mastery/overall
 * Get authenticated user's overall mastery percentage
 * Role: STUDENT (self), PARENT (linked), TUTOR, ADMIN
 */
export const getOverallMastery = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const userId = req.query.userId as string || req.user.id;

  // If requesting another user's mastery, check access
  if (userId !== req.user.id) {
    const accessibleIds = await getAccessibleStudentIds(req.user.id, req.user.role);
    if (!accessibleIds.includes(userId) && req.user.role !== "ADMIN" && req.user.role !== "TUTOR") {
      res.status(403).json({ error: "Access denied" });
      return;
    }
  }

  const overall = await masteryService.getOverallMastery(userId);
  res.json({ userId, overallMastery: overall });
});
