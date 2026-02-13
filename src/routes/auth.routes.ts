import { Router } from "express";
import {
  login,
  me,
  socialBridge,
  exchangeNeonToken,
  register,
} from "../controllers/auth.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { loginSchema, registerSchema } from "../shared/validators/index.js";

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

export { authRoutes };
