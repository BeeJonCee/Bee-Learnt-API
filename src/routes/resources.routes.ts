import { Router } from "express";
import { create, getById, list } from "../controllers/resources.controller.js";
import { requireAuth, requireRole } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { resourceCreateSchema } from "../shared/validators/index.js";

const resourcesRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Resources
 *   description: Supplemental learning resources
 */

/**
 * @swagger
 * /api/resources:
 *   get:
 *     summary: List resources available to the learner
 *     tags: [Resources]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Resource list
 */
resourcesRoutes.get("/", requireAuth, list);

/**
 * @swagger
 * /api/resources/{id}:
 *   get:
 *     summary: Get details for a resource item
 *     tags: [Resources]
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
 *         description: Resource detail
 */
resourcesRoutes.get("/:id", requireAuth, getById);

/**
 * @swagger
 * /api/resources:
 *   post:
 *     summary: Create a new resource entry
 *     tags: [Resources]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       201:
 *         description: Resource created
 */
resourcesRoutes.post("/", requireRole(["ADMIN"]), validateBody(resourceCreateSchema), create);

export { resourcesRoutes };
