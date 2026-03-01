import { Router } from "express";
import {
  login,
  me,
  updateMe,
  getAuthPreferences,
  patchAuthPreferences,
  sendVerificationCodeHandler,
  verifyVerificationCodeHandler,
  socialBridge,
  exchangeNeonToken,
  register,
  forgotPasswordHandler,
  resetPasswordHandler,
} from "./auth.controller.js";
import { requireAuth } from "../../core/middleware/auth.js";
import { validateBody } from "../../core/middleware/validate.js";
import {
  authPreferencesUpdateSchema,
  authVerificationSendSchema,
  authVerificationVerifySchema,
  loginSchema,
  registerSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from "../../shared/validators/index.js";

const authRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: Authentication and session management (Neon Auth is sole identity provider)
 */

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Authenticate a user and return a JWT (legacy + Neon Auth credential fallback)
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       401:
 *         description: Invalid email or password
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
authRoutes.post("/login", validateBody(loginSchema), login);
authRoutes.post("/register", validateBody(registerSchema), register);
authRoutes.post(
  "/verification/send",
  validateBody(authVerificationSendSchema),
  sendVerificationCodeHandler,
);
authRoutes.post(
  "/verification/verify",
  validateBody(authVerificationVerifySchema),
  verifyVerificationCodeHandler,
);
authRoutes.get("/preferences", requireAuth, getAuthPreferences);
authRoutes.patch(
  "/preferences",
  requireAuth,
  validateBody(authPreferencesUpdateSchema),
  patchAuthPreferences,
);

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Retrieve the currently authenticated user
 *     tags: [Auth]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Current user profile
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       401:
 *         description: Missing or invalid token
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
authRoutes.get("/me", requireAuth, me);
authRoutes.patch("/me", requireAuth, updateMe);
authRoutes.post("/social-bridge", socialBridge);

/**
 * @swagger
 * /api/auth/exchange-neon-token:
 *   post:
 *     summary: Exchange Neon Auth token for backend JWT
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               sessionToken:
 *                 type: string
 *                 description: Neon Auth session token (cookie token) or Neon JWT access token
 *     responses:
 *       200:
 *         description: Token exchange successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       401:
 *         description: Invalid or expired token
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
authRoutes.post("/exchange-neon-token", exchangeNeonToken);

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request a password reset link by email
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Reset link sent (always 200 to prevent email enumeration)
 */
authRoutes.post("/forgot-password", validateBody(forgotPasswordSchema), forgotPasswordHandler);

/**
 * @swagger
 * /api/auth/reset-password:
 *   post:
 *     summary: Reset password using token from the email link
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [token, newPassword]
 *             properties:
 *               token:
 *                 type: string
 *               newPassword:
 *                 type: string
 *                 minLength: 6
 *     responses:
 *       200:
 *         description: Password updated successfully
 *       400:
 *         description: Invalid or expired token
 */
authRoutes.post("/reset-password", validateBody(resetPasswordSchema), resetPasswordHandler);

export { authRoutes };
