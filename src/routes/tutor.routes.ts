/**
 * @swagger
 * tags:
 *   name: Tutor
 *   description: Tutor profile, sessions, feedback, and relationships
 */

import { Router } from "express";
import {
  getMyProfile,
  getProfile,
  createProfile,
  updateProfile,
  addExpertise,
  removeExpertise,
  listMySessions,
  createSession,
  updateSession,
  submitFeedback,
  getFeedback,
  getMyStudents,
  getMyTutors,
  connectWithStudent,
  discoverTutors,
  getAnalytics,
} from "../controllers/tutor.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import { onlyRoles, onlyAdminOrTutor } from "../core/guards/rbac.js";

const router = Router();

// ============ TUTOR PROFILE ROUTES ============

/**
 * @swagger
 * /api/tutor/profile:
 *   get:
 *     summary: Get my tutor profile
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Tutor profile
 */
router.get("/profile", requireAuth, onlyAdminOrTutor, getMyProfile);

/**
 * @swagger
 * /api/tutor/profile/{tutorId}:
 *   get:
 *     summary: Get a tutor's public profile
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: tutorId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Tutor profile
 */
router.get("/profile/:tutorId", requireAuth, getProfile);

/**
 * @swagger
 * /api/tutor/profile:
 *   post:
 *     summary: Create tutor profile (Tutor/Admin)
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Profile created
 */
router.post("/profile", requireAuth, onlyAdminOrTutor, createProfile);

/**
 * @swagger
 * /api/tutor/profile:
 *   put:
 *     summary: Update tutor profile (Tutor/Admin)
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Profile updated
 */
router.put("/profile", requireAuth, onlyAdminOrTutor, updateProfile);

// ============ EXPERTISE ROUTES ============

/**
 * @swagger
 * /api/tutor/expertise:
 *   post:
 *     summary: Add expertise (Tutor/Admin)
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Expertise added
 */
router.post("/expertise", requireAuth, onlyAdminOrTutor, addExpertise);

/**
 * @swagger
 * /api/tutor/expertise/{expertiseId}:
 *   delete:
 *     summary: Remove expertise (Tutor/Admin)
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: expertiseId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Expertise removed
 */
router.delete("/expertise/:expertiseId", requireAuth, onlyAdminOrTutor, removeExpertise);

// ============ SESSION ROUTES ============

/**
 * @swagger
 * /api/tutor/sessions:
 *   get:
 *     summary: List my tutoring sessions
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Tutoring sessions
 */
router.get("/sessions", requireAuth, onlyRoles("TUTOR", "STUDENT", "ADMIN"), listMySessions);

/**
 * @swagger
 * /api/tutor/sessions:
 *   post:
 *     summary: Create a tutoring session (Tutor/Admin)
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Session created
 */
router.post("/sessions", requireAuth, onlyAdminOrTutor, createSession);

/**
 * @swagger
 * /api/tutor/sessions/{sessionId}:
 *   put:
 *     summary: Update a tutoring session (Tutor/Admin)
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Session updated
 */
router.put("/sessions/:sessionId", requireAuth, onlyAdminOrTutor, updateSession);

// ============ FEEDBACK ROUTES ============

/**
 * @swagger
 * /api/tutor/sessions/{sessionId}/feedback:
 *   post:
 *     summary: Submit feedback for a session
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       201:
 *         description: Feedback submitted
 */
router.post(
  "/sessions/:sessionId/feedback",
  requireAuth,
  onlyRoles("STUDENT", "TUTOR", "ADMIN"),
  submitFeedback
);

/**
 * @swagger
 * /api/tutor/sessions/{sessionId}/feedback:
 *   get:
 *     summary: Get feedback for a session
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Session feedback
 */
router.get(
  "/sessions/:sessionId/feedback",
  requireAuth,
  onlyRoles("STUDENT", "TUTOR", "ADMIN"),
  getFeedback
);

// ============ RELATIONSHIP ROUTES ============

/**
 * @swagger
 * /api/tutor/students:
 *   get:
 *     summary: Get my students (Tutor/Admin)
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of students
 */
router.get("/students", requireAuth, onlyAdminOrTutor, getMyStudents);

/**
 * @swagger
 * /api/tutor/tutors:
 *   get:
 *     summary: Get my tutors (Student/Parent)
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of tutors
 */
router.get("/tutors", requireAuth, onlyRoles("STUDENT", "PARENT", "ADMIN"), getMyTutors);

/**
 * @swagger
 * /api/tutor/relationships:
 *   post:
 *     summary: Connect with a student (Tutor/Admin)
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Relationship created
 */
router.post("/relationships", requireAuth, onlyAdminOrTutor, connectWithStudent);

// ============ DISCOVERY ROUTES ============

/**
 * @swagger
 * /api/tutor/discover:
 *   get:
 *     summary: Discover available tutors
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Available tutors
 */
router.get("/discover", requireAuth, discoverTutors);

// ============ ANALYTICS ROUTES ============

/**
 * @swagger
 * /api/tutor/analytics:
 *   get:
 *     summary: Get tutor analytics (Tutor/Admin)
 *     tags: [Tutor]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Analytics data
 */
router.get("/analytics", requireAuth, onlyAdminOrTutor, getAnalytics);

export default router;
