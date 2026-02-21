import { Router } from "express";
import { list, update } from "../controllers/checklists.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { checklistProgressSchema } from "../shared/validators/index.js";

const checklistsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Checklists
 *   description: Progress checklists for modules and lessons
 */

/**
 * @swagger
 * /api/checklists:
 *   get:
 *     summary: Retrieve checklist items for the current user
 *     tags: [Checklists]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Checklist entries
 */
checklistsRoutes.get("/", requireAuth, list);

/**
 * @swagger
 * /api/checklists:
 *   post:
 *     summary: Update checklist completion states
 *     tags: [Checklists]
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
 *         description: Checklist updated
 */
checklistsRoutes.post("/", requireAuth, validateBody(checklistProgressSchema), update);

export { checklistsRoutes };
