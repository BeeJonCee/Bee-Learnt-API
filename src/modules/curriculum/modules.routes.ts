import { Router } from "express";
import { create, getById, list, remove, update } from "./modules.controller.js";
import { requireAuth, requireRole } from "../../core/middleware/auth.js";
import { validateBody } from "../../core/middleware/validate.js";
import { moduleCreateSchema, moduleUpdateSchema } from "../../shared/validators/index.js";

const modulesRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Modules
 *   description: Manage curriculum modules and related content
 */

// Public routes - allow browsing modules without authentication

/**
 * @swagger
 * /api/modules:
 *   get:
 *     summary: List published modules
 *     tags: [Modules]
 *     responses:
 *       200:
 *         description: Array of modules
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Module'
 */
modulesRoutes.get("/", list);

/**
 * @swagger
 * /api/modules/{id}:
 *   get:
 *     summary: Get a module by ID
 *     tags: [Modules]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Module identifier
 *     responses:
 *       200:
 *         description: Module details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Module'
 *       404:
 *         description: Module not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
modulesRoutes.get("/:id", getById);

// Protected routes - require admin role

/**
 * @swagger
 * /api/modules:
 *   post:
 *     summary: Create a new module
 *     tags: [Modules]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ModuleCreateRequest'
 *     responses:
 *       201:
 *         description: Module created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Module'
 *       403:
 *         description: Insufficient permissions
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
modulesRoutes.post("/", requireRole(["ADMIN", "TUTOR"]), validateBody(moduleCreateSchema), create);

/**
 * @swagger
 * /api/modules/{id}:
 *   put:
 *     summary: Update an existing module
 *     tags: [Modules]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ModuleUpdateRequest'
 *     responses:
 *       200:
 *         description: Updated module data
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Module'
 *       404:
 *         description: Module not found
 */
modulesRoutes.put("/:id", requireRole(["ADMIN", "TUTOR"]), validateBody(moduleUpdateSchema), update);

/**
 * @swagger
 * /api/modules/{id}:
 *   delete:
 *     summary: Remove a module and its associated content
 *     tags: [Modules]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Module deleted successfully
 *       404:
 *         description: Module not found
 */
modulesRoutes.delete("/:id", requireRole(["ADMIN", "TUTOR"]), remove);

export { modulesRoutes };
