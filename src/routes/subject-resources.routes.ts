import { Router } from "express";
import { list, getById, create, remove } from "../controllers/subject-resources.controller.js";
import { requireAuth, requireRole } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { subjectResourceCreateSchema } from "../shared/validators/subject-resources.validators.js";

const subjectResourcesRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: SubjectResources
 *   description: Grade-level subject resources (textbooks, guides, data files)
 */

/**
 * @swagger
 * /api/subject-resources:
 *   get:
 *     summary: List subject resources
 *     tags: [SubjectResources]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: subjectId
 *         schema:
 *           type: integer
 *       - in: query
 *         name: gradeId
 *         schema:
 *           type: integer
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Resource list
 */
subjectResourcesRoutes.get("/", requireAuth, list);

/**
 * @swagger
 * /api/subject-resources/{id}:
 *   get:
 *     summary: Get a subject resource by ID
 *     tags: [SubjectResources]
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
subjectResourcesRoutes.get("/:id", requireAuth, getById);

/**
 * @swagger
 * /api/subject-resources:
 *   post:
 *     summary: Create a subject resource
 *     tags: [SubjectResources]
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
subjectResourcesRoutes.post(
  "/",
  requireRole(["ADMIN"]),
  validateBody(subjectResourceCreateSchema),
  create
);

/**
 * @swagger
 * /api/subject-resources/{id}:
 *   delete:
 *     summary: Delete a subject resource
 *     tags: [SubjectResources]
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
 *         description: Resource deleted
 */
subjectResourcesRoutes.delete("/:id", requireRole(["ADMIN"]), remove);

export { subjectResourcesRoutes };
