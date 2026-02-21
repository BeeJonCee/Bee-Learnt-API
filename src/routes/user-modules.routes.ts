import { Router } from "express";
import { listUserModules } from "../controllers/user-modules.controller.js";
import { requireAuth } from "../core/middleware/auth.js";

const userModulesRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: User Modules
 *   description: Current user's module list
 */

/**
 * @swagger
 * /api/user-modules:
 *   get:
 *     summary: List modules for the current user
 *     tags: [User Modules]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: User's modules
 */
userModulesRoutes.get("/", requireAuth, listUserModules);

export { userModulesRoutes };
