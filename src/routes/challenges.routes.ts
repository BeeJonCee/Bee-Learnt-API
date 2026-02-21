import { Router } from "express";
import { requireAuth } from "../core/middleware/auth.js";
import { getChallenges, initializeChallenges } from "../controllers/challenges.controller.js";

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Challenges
 *   description: Learning challenges and quest progression
 */

// All routes require authentication
router.use(requireAuth);

/**
 * @swagger
 * /api/challenges:
 *   get:
 *     summary: Retrieve active challenges for the current user
 *     tags: [Challenges]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Active challenges
 */
router.get("/", getChallenges);

/**
 * @swagger
 * /api/challenges/initialize:
 *   post:
 *     summary: Initialise default challenge sets
 *     tags: [Challenges]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Challenges initialised
 */
router.post("/initialize", initializeChallenges);

export { router as challengesRoutes };
