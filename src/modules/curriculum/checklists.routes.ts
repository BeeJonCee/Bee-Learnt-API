import { Router } from "express";
import { requireAuth } from "../../core/middleware/auth.js";
import { list, update } from "./checklists.controller.js";

const checklistsRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Checklists
 *   description: Module checklist progress tracking
 */

/**
 * @swagger
 * /api/checklists:
 *   get:
 *     summary: List checklist items for a module with user progress
 *     tags: [Checklists]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: moduleId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Checklist items with completion status
 */
checklistsRoutes.get("/", requireAuth, list);

/**
 * @swagger
 * /api/checklists/progress:
 *   post:
 *     summary: Update checklist item progress for the current user
 *     tags: [Checklists]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [itemId, completed]
 *             properties:
 *               itemId:
 *                 type: integer
 *               completed:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Progress updated
 *       201:
 *         description: Progress created
 */
checklistsRoutes.post("/progress", requireAuth, update);

export { checklistsRoutes };
