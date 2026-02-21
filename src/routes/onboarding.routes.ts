import { Router } from "express";
import {
  listModules,
  requestModuleCode,
  selectModule,
} from "../controllers/onboarding.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import {
  onboardingRequestCodeSchema,
  onboardingSelectSchema,
} from "../shared/validators/index.js";

const onboardingRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Onboarding
 *   description: New learner onboarding flows
 */

/**
 * @swagger
 * /api/onboarding/modules:
 *   get:
 *     summary: List recommended modules during onboarding
 *     tags: [Onboarding]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Available modules for onboarding
 */
onboardingRoutes.get("/modules", requireAuth, listModules);

/**
 * @swagger
 * /api/onboarding/select:
 *   post:
 *     summary: Select a module as part of onboarding
 *     tags: [Onboarding]
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
 *         description: Module selected successfully
 */
onboardingRoutes.post("/select", requireAuth, validateBody(onboardingSelectSchema), selectModule);

/**
 * @swagger
 * /api/onboarding/request-code:
 *   post:
 *     summary: Request today's unlock code to be emailed to admin
 *     tags: [Onboarding]
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
 *         description: Access code requested successfully
 */
onboardingRoutes.post(
  "/request-code",
  requireAuth,
  validateBody(onboardingRequestCodeSchema),
  requestModuleCode
);

export { onboardingRoutes };
