import { Router } from "express";
import { requireAuth, requireRole } from "../core/middleware/auth.js";
import { validateBody, validateQuery } from "../core/middleware/validate.js";
import {
  curriculumCreateSchema,
  curriculumUpdateSchema,
  gradeCreateSchema,
  gradeUpdateSchema,
  topicCreateSchema,
  topicUpdateSchema,
  topicListQuerySchema,
  learningOutcomeCreateSchema,
  learningOutcomeUpdateSchema,
} from "../shared/validators/index.js";
import {
  listCurriculaHandler,
  getCurriculumHandler,
  createCurriculumHandler,
  updateCurriculumHandler,
  deleteCurriculumHandler,
  listGradesHandler,
  getGradeHandler,
  createGradeHandler,
  updateGradeHandler,
  deleteGradeHandler,
  listTopicsHandler,
  getTopicHandler,
  createTopicHandler,
  updateTopicHandler,
  deleteTopicHandler,
  listOutcomesHandler,
  getOutcomeHandler,
  createOutcomeHandler,
  updateOutcomeHandler,
  deleteOutcomeHandler,
} from "../controllers/curriculum.controller.js";

const curriculumRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Curriculum
 *   description: Curricula, grades, topics, and learning outcomes
 */

// ============ CURRICULA ============

/**
 * @swagger
 * /api/curriculum/curricula:
 *   get:
 *     summary: List all curricula
 *     tags: [Curriculum]
 *     responses:
 *       200:
 *         description: List of curricula
 */
curriculumRoutes.get("/curricula", listCurriculaHandler);

/**
 * @swagger
 * /api/curriculum/curricula/{id}:
 *   get:
 *     summary: Get a curriculum by ID
 *     tags: [Curriculum]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Curriculum details
 */
curriculumRoutes.get("/curricula/:id", getCurriculumHandler);

/**
 * @swagger
 * /api/curriculum/curricula:
 *   post:
 *     summary: Create a curriculum (Admin only)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, country]
 *             properties:
 *               name:
 *                 type: string
 *               country:
 *                 type: string
 *               description:
 *                 type: string
 *     responses:
 *       201:
 *         description: Created
 */
curriculumRoutes.post(
  "/curricula",
  requireAuth,
  requireRole(["ADMIN"]),
  validateBody(curriculumCreateSchema),
  createCurriculumHandler
);

/**
 * @swagger
 * /api/curriculum/curricula/{id}:
 *   put:
 *     summary: Update a curriculum (Admin only)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Updated
 */
curriculumRoutes.put(
  "/curricula/:id",
  requireAuth,
  requireRole(["ADMIN"]),
  validateBody(curriculumUpdateSchema),
  updateCurriculumHandler
);

/**
 * @swagger
 * /api/curriculum/curricula/{id}:
 *   delete:
 *     summary: Delete a curriculum (Admin only)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Deleted
 */
curriculumRoutes.delete(
  "/curricula/:id",
  requireAuth,
  requireRole(["ADMIN"]),
  deleteCurriculumHandler
);

// ============ GRADES ============

/**
 * @swagger
 * /api/curriculum/grades:
 *   get:
 *     summary: List all grades
 *     tags: [Curriculum]
 *     responses:
 *       200:
 *         description: List of grades
 */
curriculumRoutes.get("/grades", listGradesHandler);

/**
 * @swagger
 * /api/curriculum/grades/{id}:
 *   get:
 *     summary: Get a grade by ID
 *     tags: [Curriculum]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Grade details
 */
curriculumRoutes.get("/grades/:id", getGradeHandler);

/**
 * @swagger
 * /api/curriculum/grades:
 *   post:
 *     summary: Create a grade (Admin only)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Created
 */
curriculumRoutes.post(
  "/grades",
  requireAuth,
  requireRole(["ADMIN"]),
  validateBody(gradeCreateSchema),
  createGradeHandler
);

/**
 * @swagger
 * /api/curriculum/grades/{id}:
 *   put:
 *     summary: Update a grade (Admin only)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Updated
 */
curriculumRoutes.put(
  "/grades/:id",
  requireAuth,
  requireRole(["ADMIN"]),
  validateBody(gradeUpdateSchema),
  updateGradeHandler
);

/**
 * @swagger
 * /api/curriculum/grades/{id}:
 *   delete:
 *     summary: Delete a grade (Admin only)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Deleted
 */
curriculumRoutes.delete(
  "/grades/:id",
  requireAuth,
  requireRole(["ADMIN"]),
  deleteGradeHandler
);

// ============ TOPICS ============

/**
 * @swagger
 * /api/curriculum/topics:
 *   get:
 *     summary: List topics
 *     tags: [Curriculum]
 *     parameters:
 *       - in: query
 *         name: subjectId
 *         schema:
 *           type: integer
 *       - in: query
 *         name: gradeId
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of topics
 */
curriculumRoutes.get("/topics", validateQuery(topicListQuerySchema), listTopicsHandler);

/**
 * @swagger
 * /api/curriculum/topics/{id}:
 *   get:
 *     summary: Get a topic by ID
 *     tags: [Curriculum]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Topic details
 */
curriculumRoutes.get("/topics/:id", getTopicHandler);

/**
 * @swagger
 * /api/curriculum/topics:
 *   post:
 *     summary: Create a topic (Admin/Tutor)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Created
 */
curriculumRoutes.post(
  "/topics",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  validateBody(topicCreateSchema),
  createTopicHandler
);

/**
 * @swagger
 * /api/curriculum/topics/{id}:
 *   put:
 *     summary: Update a topic (Admin/Tutor)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Updated
 */
curriculumRoutes.put(
  "/topics/:id",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  validateBody(topicUpdateSchema),
  updateTopicHandler
);

/**
 * @swagger
 * /api/curriculum/topics/{id}:
 *   delete:
 *     summary: Delete a topic (Admin only)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Deleted
 */
curriculumRoutes.delete(
  "/topics/:id",
  requireAuth,
  requireRole(["ADMIN"]),
  deleteTopicHandler
);

// ============ LEARNING OUTCOMES ============

/**
 * @swagger
 * /api/curriculum/topics/{topicId}/outcomes:
 *   get:
 *     summary: List learning outcomes for a topic
 *     tags: [Curriculum]
 *     parameters:
 *       - in: path
 *         name: topicId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of outcomes
 */
curriculumRoutes.get("/topics/:topicId/outcomes", listOutcomesHandler);

/**
 * @swagger
 * /api/curriculum/outcomes/{id}:
 *   get:
 *     summary: Get a learning outcome by ID
 *     tags: [Curriculum]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Outcome details
 */
curriculumRoutes.get("/outcomes/:id", getOutcomeHandler);

/**
 * @swagger
 * /api/curriculum/topics/{topicId}/outcomes:
 *   post:
 *     summary: Create a learning outcome (Admin/Tutor)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: topicId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       201:
 *         description: Created
 */
curriculumRoutes.post(
  "/topics/:topicId/outcomes",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  validateBody(learningOutcomeCreateSchema),
  createOutcomeHandler
);

/**
 * @swagger
 * /api/curriculum/outcomes/{id}:
 *   put:
 *     summary: Update a learning outcome (Admin/Tutor)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Updated
 */
curriculumRoutes.put(
  "/outcomes/:id",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  validateBody(learningOutcomeUpdateSchema),
  updateOutcomeHandler
);

/**
 * @swagger
 * /api/curriculum/outcomes/{id}:
 *   delete:
 *     summary: Delete a learning outcome (Admin only)
 *     tags: [Curriculum]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Deleted
 */
curriculumRoutes.delete(
  "/outcomes/:id",
  requireAuth,
  requireRole(["ADMIN"]),
  deleteOutcomeHandler
);

export { curriculumRoutes };
