/**
 * @swagger
 * tags:
 *   name: Module Unlock
 *   description: Daily token-based module unlocking system
 */

import { Router } from "express";
import {
  generateModuleToken,
  requestModuleToken,
  unlockModule,
  getTokenStatus,
  getModuleTokenInfo,
} from "../controllers/module-unlock.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import { onlyRoles, onlyAdminOrTutor, onlyStudent } from "../core/guards/rbac.js";

const router = Router();

/**
 * @swagger
 * /api/module-unlock/generate:
 *   post:
 *     summary: Generate token for a module assignment (Tutor/Admin)
 *     tags: [Module Unlock]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Token generated
 */
router.post(
  "/module-unlock/generate",
  requireAuth,
  onlyAdminOrTutor,
  generateModuleToken
);

/**
 * @swagger
 * /api/module-unlock/request:
 *   post:
 *     summary: Request a token for a module
 *     tags: [Module Unlock]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Token request submitted
 */
router.post(
  "/module-unlock/request",
  requireAuth,
  requestModuleToken
);

/**
 * @swagger
 * /api/module-unlock/unlock:
 *   post:
 *     summary: Unlock a module using a token (Students only)
 *     tags: [Module Unlock]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Module unlocked
 */
router.post(
  "/module-unlock/unlock",
  requireAuth,
  onlyStudent,
  unlockModule
);

/**
 * @swagger
 * /api/module-unlock/status/{assignmentId}:
 *   get:
 *     summary: Get token status for an assignment
 *     tags: [Module Unlock]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: assignmentId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Token status
 */
router.get(
  "/module-unlock/status/:assignmentId",
  requireAuth,
  getTokenStatus
);

/**
 * @swagger
 * /api/module-unlock/token/{assignmentId}:
 *   get:
 *     summary: Get token info (Tutor/Admin)
 *     tags: [Module Unlock]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: assignmentId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Token info
 */
router.get(
  "/module-unlock/token/:assignmentId",
  requireAuth,
  onlyAdminOrTutor,
  getModuleTokenInfo
);

export default router;
