import { Router } from "express";
import { getAccessibility, updateAccessibility } from "../controllers/accessibility.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { accessibilityUpdateSchema } from "../shared/validators/index.js";

const accessibilityRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Accessibility
 *   description: Personalised accessibility preferences for learners
 */

/**
 * @swagger
 * /api/accessibility:
 *   get:
 *     summary: Retrieve the current user's accessibility preferences
 *     tags: [Accessibility]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Accessibility configuration for the authenticated user
 */
accessibilityRoutes.get("/", requireAuth, getAccessibility);

/**
 * @swagger
 * /api/accessibility:
 *   put:
 *     summary: Update accessibility settings for the current user
 *     tags: [Accessibility]
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
 *         description: Updated accessibility preferences
 */
accessibilityRoutes.put("/", requireAuth, validateBody(accessibilityUpdateSchema), updateAccessibility);

export { accessibilityRoutes };
