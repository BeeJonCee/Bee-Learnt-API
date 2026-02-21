import { Router, Request, Response } from "express";
import { requireAuth } from "../core/middleware/auth.js";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { validateBody } from "../core/middleware/validate.js";
import { z } from "zod";
import * as goalsService from "../services/student-goals.service.js";
import * as performanceService from "../services/student-performance.service.js";

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Student
 *   description: Student self-service goals, performance, and resources
 */

// =============================================================================
// STUDY GOALS ROUTES
// =============================================================================

/**
 * GET /api/student/goals
 * Get all study goals for the authenticated student
 */
/**
 * @swagger
 * /api/student/goals:
 *   get:
 *     summary: List study goals for the authenticated student
 *     tags: [Student]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Study goals collection
 */
router.get(
  "/goals",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const goals = await goalsService.getStudentGoals(userId);
    res.json(goals);
  })
);

/**
 * POST /api/student/goals
 * Create a new study goal
 */
const createGoalSchema = z.object({
  title: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  targetHours: z.number().positive(),
  deadline: z.string().datetime(),
  priority: z.enum(["low", "medium", "high"]),
});

/**
 * @swagger
 * /api/student/goals:
 *   post:
 *     summary: Create a new study goal
 *     tags: [Student]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: "#/components/schemas/StudentGoalCreateRequest"
 *     responses:
 *       201:
 *         description: Goal created
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/StudentGoal"
 */
router.post(
  /**
   * @swagger
   * /api/student/goals:
   *   post:
   *     summary: Create a new study goal
   *     tags: [Student]
   *     security:
   *       - BearerAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/StudentGoalCreateRequest'
   *     responses:
   *       201:
   *         description: Goal created successfully
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/StudentGoal'
   */
  "/goals",
  requireAuth,
  validateBody(createGoalSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const goal = await goalsService.createStudyGoal(userId, req.body);
    res.status(201).json(goal);
  })
);

/**
 * PATCH /api/student/goals/:goalId
 * Update a study goal
 */
const updateGoalSchema = z.object({
  title: z.string().min(1).max(255).optional(),
  description: z.string().max(1000).optional(),
  targetHours: z.number().positive().optional(),
  currentHours: z.number().nonnegative().optional(),
  deadline: z.string().datetime().optional(),
  priority: z.enum(["low", "medium", "high"]).optional(),
  status: z.enum(["active", "completed", "overdue"]).optional(),
});

/**
 * @swagger
 * /api/student/goals/{goalId}:
 *   patch:
 *     summary: Update a study goal
 *     tags: [Student]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: goalId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: "#/components/schemas/StudentGoalUpdateRequest"
 *     responses:
 *       200:
 *         description: Updated goal
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/StudentGoal"
 */
router.patch(
  /**
   * @swagger
   * /api/student/goals/{goalId}:
   *   patch:
   *     summary: Update a study goal
   *     tags: [Student]
   *     security:
   *       - BearerAuth: []
   *     parameters:
   *       - in: path
   *         name: goalId
   *         required: true
   *         schema:
   *           type: string
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/StudentGoalUpdateRequest'
   *     responses:
   *       200:
   *         description: Updated goal details
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/StudentGoal'
   */
  "/goals/:goalId",
  requireAuth,
  validateBody(updateGoalSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const goalId = req.params.goalId as string;

    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const goal = await goalsService.updateStudyGoal(goalId, userId, req.body);
    res.json(goal);
  })
);

/**
 * DELETE /api/student/goals/:goalId
 * Delete a study goal
 */
/**
 * @swagger
 * /api/student/goals/{goalId}:
 *   delete:
 *     summary: Remove a study goal
 *     tags: [Student]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: goalId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       204:
 *         description: Goal deleted
 */
router.delete(
  /**
   * @swagger
   * /api/student/goals/{goalId}:
   *   delete:
   *     summary: Delete a study goal
   *     tags: [Student]
   *     security:
   *       - BearerAuth: []
   *     parameters:
   *       - in: path
   *         name: goalId
   *         required: true
   *         schema:
   *           type: string
   *     responses:
   *       204:
   *         description: Goal removed successfully
   */
  "/goals/:goalId",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const goalId = req.params.goalId as string;

    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    await goalsService.deleteStudyGoal(goalId, userId);
    res.status(204).send();
  })
);

/**
 * PATCH /api/student/goals/:goalId/complete
 * Mark a goal as completed
 */
/**
 * @swagger
 * /api/student/goals/{goalId}/complete:
 *   patch:
 *     summary: Mark goal as completed
 *     tags: [Student]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: goalId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Completed goal
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/StudentGoal"
 */
router.patch(
  /**
   * @swagger
   * /api/student/goals/{goalId}/complete:
   *   patch:
   *     summary: Mark a study goal as completed
   *     tags: [Student]
   *     security:
   *       - BearerAuth: []
   *     parameters:
   *       - in: path
   *         name: goalId
   *         required: true
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Goal marked as complete
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/StudentGoal'
   */
  "/goals/:goalId/complete",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const goalId = req.params.goalId as string;

    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const goal = await goalsService.completeStudyGoal(goalId, userId);
    res.json(goal);
  })
);

/**
 * PATCH /api/student/goals/:goalId/progress
 * Update goal progress with logged hours
 */
const updateProgressSchema = z.object({
  hoursSpent: z.number().positive(),
});

/**
 * @swagger
 * /api/student/goals/{goalId}/progress:
 *   patch:
 *     summary: Log progress against a goal
 *     tags: [Student]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: goalId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: "#/components/schemas/StudentGoalProgressRequest"
 *     responses:
 *       200:
 *         description: Goal with updated progress
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/StudentGoal"
 */
router.patch(
  /**
   * @swagger
   * /api/student/goals/{goalId}/progress:
   *   patch:
   *     summary: Log progress toward a study goal
   *     tags: [Student]
   *     security:
   *       - BearerAuth: []
   *     parameters:
   *       - in: path
   *         name: goalId
   *         required: true
   *         schema:
   *           type: string
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/StudentGoalProgressUpdateRequest'
   *     responses:
   *       200:
   *         description: Updated goal progress
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/StudentGoal'
   */
  "/goals/:goalId/progress",
  requireAuth,
  validateBody(updateProgressSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const goalId = req.params.goalId as string;
    const { hoursSpent } = req.body;

    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const goal = await goalsService.updateGoalProgress(goalId, userId, hoursSpent);
    res.json(goal);
  })
);

// =============================================================================
// PERFORMANCE ROUTES
// =============================================================================

// =============================================================================
// PERFORMANCE ROUTES
// =============================================================================

/**
 * GET /api/student/performance
 * Get comprehensive performance analytics for the student
 */
/**
 * @swagger
 * /api/student/performance:
 *   get:
 *     summary: Retrieve performance analytics for the student
 *     tags: [Student]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Performance snapshot
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/StudentPerformance"
 */
router.get(
  /**
   * @swagger
   * /api/student/performance:
   *   get:
   *     summary: Retrieve the student's performance overview
   *     tags: [Student]
   *     security:
   *       - BearerAuth: []
   *     responses:
   *       200:
   *         description: Performance analytics for the student
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/StudentPerformance'
   */
  "/performance",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const performance = await performanceService.getStudentPerformance(userId);
    res.json(performance);
  })
);

/**
 * GET /api/student/performance/subject/:subjectId
 * Get detailed analytics for a specific subject
 */
/**
 * @swagger
 * /api/student/performance/subject/{subjectId}:
 *   get:
 *     summary: Retrieve analytics for a specific subject
 *     tags: [Student]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: subjectId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Subject analytics
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: "#/components/schemas/StudentSubjectAnalytics"
 */
router.get(
  /**
   * @swagger
   * /api/student/performance/subject/{subjectId}:
   *   get:
   *     summary: Retrieve detailed performance analytics for a subject
   *     tags: [Student]
   *     security:
   *       - BearerAuth: []
   *     parameters:
   *       - in: path
   *         name: subjectId
   *         required: true
   *         schema:
   *           type: integer
   *     responses:
   *       200:
   *         description: Subject-level analytics
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/StudentSubjectPerformance'
   */
  "/performance/subject/:subjectId",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const subjectId = req.params.subjectId as string;

    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const analytics = await performanceService.getSubjectAnalytics(
      userId,
      parseInt(subjectId)
    );
    res.json(analytics);
  })
);

// =============================================================================
// LEARNING PATHS ROUTES
// =============================================================================

/**
 * GET /api/student/learning-paths
 * Get all learning paths for the student (active, completed, recommended)
 */
/**
 * @swagger
 * /api/student/learning-paths:
 *   get:
 *     summary: List learning paths for the student
 *     tags: [Student]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Learning path collections
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/StudentLearningPathsResponse"
 */
router.get(
  /**
   * @swagger
   * /api/student/learning-paths:
   *   get:
   *     summary: List learning paths for the student
   *     tags: [Student]
   *     security:
   *       - BearerAuth: []
   *     responses:
   *       200:
   *         description: Learning paths grouped by status
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/StudentLearningPathsResponse'
   */
  "/learning-paths",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    // Mock data - replace with actual database queries
    const mockPaths = {
      active: [
        {
          id: "path_1",
          name: "Mathematics Fundamentals",
          description: "Master core mathematical concepts and problem-solving techniques",
          subject: "Mathematics",
          grade: "Grade 10",
          difficulty: "beginner" as const,
          totalHours: 40,
          completedHours: 24,
          progress: 60,
          enrolledDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
          estimatedCompletion: new Date(Date.now() + 16 * 24 * 60 * 60 * 1000).toISOString(),
          certificateAvailable: true,
          milestones: [
            {
              id: "m1",
              title: "Algebra Basics",
              description: "Learn fundamental algebraic expressions and equations",
              status: "completed" as const,
              completedDate: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString(),
              estimatedHours: 8,
              actualHours: 8,
              modules: 3,
              lessons: 12,
            },
            {
              id: "m2",
              title: "Geometry Introduction",
              description: "Explore shapes, angles, and spatial reasoning",
              status: "in_progress" as const,
              estimatedHours: 8,
              actualHours: 6,
              modules: 3,
              lessons: 10,
            },
            {
              id: "m3",
              title: "Trigonometry Basics",
              description: "Understanding triangles and trigonometric functions",
              status: "not_started" as const,
              estimatedHours: 12,
              actualHours: 0,
              modules: 4,
              lessons: 14,
            },
            {
              id: "m4",
              title: "Calculus Foundations",
              description: "Introduction to limits, derivatives, and integration",
              status: "not_started" as const,
              estimatedHours: 12,
              actualHours: 0,
              modules: 4,
              lessons: 15,
            },
          ],
          skillsGained: [
            "Algebraic Problem Solving",
            "Geometric Visualization",
            "Trigonometric Functions",
            "Calculus Fundamentals",
          ],
        },
      ],
      completed: [
        {
          id: "path_2",
          name: "English Literature Essentials",
          description: "Comprehensive exploration of classic and contemporary literature",
          subject: "English",
          grade: "Grade 9",
          difficulty: "beginner" as const,
          totalHours: 36,
          completedHours: 36,
          progress: 100,
          enrolledDate: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
          estimatedCompletion: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString(),
          certificateAvailable: true,
          milestones: [],
          skillsGained: ["Literary Analysis", "Essay Writing", "Critical Thinking"],
        },
      ],
      recommended: [
        {
          id: "path_3",
          name: "Physics Fundamentals",
          description: "Core physics concepts including mechanics and waves",
          subject: "Physics",
          grade: "Grade 11",
          difficulty: "intermediate" as const,
          totalHours: 50,
          completedHours: 0,
          progress: 0,
          enrolledDate: new Date().toISOString(),
          estimatedCompletion: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
          certificateAvailable: true,
          milestones: [],
          skillsGained: [],
        },
        {
          id: "path_4",
          name: "Chemistry Essentials",
          description: "Understanding atomic structure, bonding, and reactions",
          subject: "Chemistry",
          grade: "Grade 10",
          difficulty: "intermediate" as const,
          totalHours: 45,
          completedHours: 0,
          progress: 0,
          enrolledDate: new Date().toISOString(),
          estimatedCompletion: new Date(Date.now() + 55 * 24 * 60 * 60 * 1000).toISOString(),
          certificateAvailable: true,
          milestones: [],
          skillsGained: [],
        },
      ],
      progressOverTime: [
        { date: "2024-01-01", hoursCompleted: 2, pathsActive: 0 },
        { date: "2024-01-08", hoursCompleted: 4, pathsActive: 1 },
        { date: "2024-01-15", hoursCompleted: 6, pathsActive: 1 },
        { date: "2024-01-22", hoursCompleted: 8, pathsActive: 1 },
        { date: "2024-01-29", hoursCompleted: 12, pathsActive: 1 },
        { date: "2024-02-05", hoursCompleted: 18, pathsActive: 1 },
        { date: "2024-02-12", hoursCompleted: 24, pathsActive: 1 },
      ],
    };

    res.json(mockPaths);
  })
);

/**
 * POST /api/student/learning-paths/:pathId/enroll
 * Enroll in a learning path
 */
router.post(
  /**
   * @swagger
   * /api/student/learning-paths/{pathId}/enroll:
   *   post:
   *     summary: Enroll the student in a learning path
   *     tags: [Student]
   *     security:
   *       - BearerAuth: []
   *     parameters:
   *       - in: path
   *         name: pathId
   *         required: true
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Enrollment acknowledged
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/OperationResponse'
   */
  "/learning-paths/:pathId/enroll",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const { pathId } = req.params;

    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    // Mock enrollment - in production, save to database
    res.json({ success: true, message: `Enrolled in path ${pathId}` });
  })
);

// =============================================================================
// RECOMMENDED RESOURCES ROUTES
// =============================================================================

/**
 * GET /api/student/recommended-resources
 * Get recommended learning resources for the student
 */
router.get(
  /**
   * @swagger
   * /api/student/recommended-resources:
   *   get:
   *     summary: Get personalized resource recommendations for the student
   *     tags: [Student]
   *     security:
   *       - BearerAuth: []
   *     responses:
   *       200:
   *         description: Recommended learning resources
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/StudentRecommendedResourcesResponse'
   */
  "/recommended-resources",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const mockResources = {
      personalized: [
        {
          id: "res_1",
          title: "Advanced Algebra Techniques",
          description: "Master advanced algebraic methods for complex equations",
          type: "video" as const,
          subject: "Mathematics",
          topic: "Algebra",
          url: "https://youtube.com/watch?v=example1",
          difficulty: "intermediate" as const,
          duration: 45,
          rating: 4.8,
          reviews: 320,
          relevanceScore: 95,
          saved: false,
        },
        {
          id: "res_2",
          title: "Geometry Problem Solving Workshop",
          description: "Interactive problems and solutions for geometric concepts",
          type: "interactive" as const,
          subject: "Mathematics",
          topic: "Geometry",
          url: "https://example.com/geometry-workshop",
          difficulty: "beginner" as const,
          duration: 60,
          rating: 4.6,
          reviews: 250,
          relevanceScore: 88,
          saved: true,
        },
        {
          id: "res_3",
          title: "Trigonometry Fundamentals",
          description: "Complete guide to sin, cos, tan and their applications",
          type: "textbook" as const,
          subject: "Mathematics",
          topic: "Trigonometry",
          url: "https://example.com/trig-book",
          difficulty: "beginner" as const,
          duration: 120,
          rating: 4.5,
          reviews: 180,
          relevanceScore: 82,
          saved: false,
        },
      ],
      trending: [
        {
          id: "res_4",
          title: "AI and Machine Learning Basics",
          description: "Introduction to ML algorithms and neural networks",
          type: "article" as const,
          subject: "Computer Science",
          topic: "AI/ML",
          url: "https://example.com/ai-basics",
          difficulty: "intermediate" as const,
          duration: 30,
          rating: 4.9,
          reviews: 890,
          relevanceScore: 65,
          saved: false,
        },
        {
          id: "res_5",
          title: "Data Visualization with Python",
          description: "Create stunning visualizations using Matplotlib and Seaborn",
          type: "video" as const,
          subject: "Computer Science",
          topic: "Data Science",
          url: "https://youtube.com/watch?v=example2",
          difficulty: "intermediate" as const,
          duration: 55,
          rating: 4.7,
          reviews: 650,
          relevanceScore: 72,
          saved: false,
        },
      ],
      byDifficulty: {
        beginner: [
          {
            id: "res_6",
            title: "Basic Equations Explained",
            description: "Easy-to-understand explanation of linear equations",
            type: "video" as const,
            subject: "Mathematics",
            topic: "Algebra",
            url: "https://youtube.com/watch?v=example3",
            difficulty: "beginner" as const,
            duration: 25,
            rating: 4.4,
            reviews: 420,
            relevanceScore: 78,
            saved: false,
          },
        ],
        intermediate: [
          {
            id: "res_7",
            title: "Calculus for Engineering",
            description: "Applied calculus concepts for engineering problems",
            type: "article" as const,
            subject: "Mathematics",
            topic: "Calculus",
            url: "https://example.com/calc-eng",
            difficulty: "intermediate" as const,
            duration: 90,
            rating: 4.6,
            reviews: 310,
            relevanceScore: 80,
            saved: false,
          },
        ],
        advanced: [
          {
            id: "res_8",
            title: "Differential Equations Mastery",
            description: "Advanced techniques for solving differential equations",
            type: "textbook" as const,
            subject: "Mathematics",
            topic: "Calculus",
            url: "https://example.com/diff-eq",
            difficulty: "advanced" as const,
            duration: 180,
            rating: 4.8,
            reviews: 195,
            relevanceScore: 75,
            saved: false,
          },
        ],
      },
      categoryStats: [
        { name: "Videos", resources: 45, avgRating: 4.6 },
        { name: "Articles", resources: 32, avgRating: 4.5 },
        { name: "Textbooks", resources: 18, avgRating: 4.7 },
        { name: "Interactive", resources: 25, avgRating: 4.4 },
      ],
    };

    res.json(mockResources);
  })
);

/**
 * PATCH /api/student/resources/:resourceId/save
 * Save/unsave a resource
 */
router.patch(
  /**
   * @swagger
   * /api/student/resources/{resourceId}/save:
   *   patch:
   *     summary: Save or unsave a learning resource for the student
   *     tags: [Student]
   *     security:
   *       - BearerAuth: []
   *     parameters:
   *       - in: path
   *         name: resourceId
   *         required: true
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Current save state of the resource
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/OperationResponse'
   */
  "/resources/:resourceId/save",
  requireAuth,
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const { resourceId } = req.params;

    if (!userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    // Mock save - in production, save to database
    res.json({ success: true, message: `Resource ${resourceId} saved` });
  })
);

export default router;
