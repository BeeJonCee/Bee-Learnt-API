import { Router } from "express";
import { search } from "../controllers/search.controller.js";
import { requireAuth } from "../core/middleware/auth.js";

const searchRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Search
 *   description: Cross-platform search endpoints
 */

/**
 * @swagger
 * /api/search:
 *   get:
 *     summary: Perform a global platform search
 *     tags: [Search]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: q
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Search results
 */
searchRoutes.get("/", requireAuth, search);

export { searchRoutes };
