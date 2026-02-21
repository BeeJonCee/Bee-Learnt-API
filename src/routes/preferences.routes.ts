import { Router } from "express";
import { requireAuth } from "../core/middleware/auth.js";
import { getPreferences, patchPreferences } from "../controllers/preferences.controller.js";

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Preferences
 *   description: Personal preference settings
 */

// All routes require authentication
router.use(requireAuth);

/**
 * @swagger
 * /api/preferences:
 *   get:
 *     summary: Retrieve the signed-in user's preferences
 *     tags: [Preferences]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Preference settings
 */
router.get("/", getPreferences);

/**
 * @swagger
 * /api/preferences:
 *   patch:
 *     summary: Update preference settings
 *     tags: [Preferences]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Preferences updated
 */
router.patch("/", patchPreferences);

export { router as preferencesRoutes };
