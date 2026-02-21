import { Router } from "express";
import { educationFeed } from "./external.controller.js";

const externalRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: External
 *   description: External data feeds and resources
 */

/**
 * @swagger
 * /api/external/feed:
 *   get:
 *     summary: Get education news feed
 *     tags: [External]
 *     responses:
 *       200:
 *         description: Education news feed items
 */
externalRoutes.get("/feed", educationFeed);

export { externalRoutes };
