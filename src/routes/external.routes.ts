import { Router } from "express";
import { educationFeed } from "../controllers/external.controller.js";
import { requireAuth } from "../core/middleware/auth.js";

const externalRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: External
 *   description: External integrations and data sources
 */

/**
 * @swagger
 * /api/external/education-feed:
 *   get:
 *     summary: Curated education news feed
 *     tags: [External]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Education feed items
 */
externalRoutes.get("/education-feed", requireAuth, educationFeed);

export { externalRoutes };
