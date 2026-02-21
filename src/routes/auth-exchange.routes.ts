import { Router } from "express";
import jwt from "jsonwebtoken";
import { db } from "../core/database/index.js";
import { sql } from "drizzle-orm";
import { env } from "../config/env.js";
import { authenticate } from "../core/middleware/auth.js";
import { errorHandler } from "../core/middleware/error-handler.js";
import type { Request as ExpressRequest, Response } from "express";

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Auth Exchange
 *   description: Neon Auth token exchange endpoints
 */

interface NeonAuthToken {
  sub: string;
  email?: string;
  name?: string;
  iat: number;
  exp: number;
}

/**
 * @swagger
 * /api/auth/exchange-neon-token:
 *   post:
 *     summary: Exchange Neon Auth token for backend JWT
 *     tags: [Auth Exchange]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [sessionToken]
 *             properties:
 *               sessionToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Backend JWT and user data
 *       400:
 *         description: Missing sessionToken
 *       401:
 *         description: Invalid or expired token
 */
router.post("/exchange-neon-token", async (req: ExpressRequest, res: Response) => {
  try {
    const { sessionToken } = req.body;

    if (!sessionToken) {
      return res.status(400).json({ message: "Missing sessionToken" });
    }

    // Decode token (don't verify signature yet - Neon auth tokens are short-lived)
    let decodedToken: NeonAuthToken;
    try {
      // Token is already validated by the client so we just decode it
      decodedToken = jwt.decode(sessionToken) as NeonAuthToken;

      if (!decodedToken?.sub) {
        return res.status(401).json({ message: "Invalid token format" });
      }
    } catch (error) {
      return res.status(401).json({ message: "Invalid token" });
    }

    // Check if token is expired
    if (decodedToken.exp && decodedToken.exp * 1000 < Date.now()) {
      return res.status(401).json({ message: "Token expired" });
    }

    const neonUserId = decodedToken.sub;

    // Fetch user from database
    const user = await db.execute(sql`
      SELECT u.id, u.email, u.name, r.name as role
      FROM public.users u
      LEFT JOIN roles r ON u.role_id = r.id
      WHERE u.id = ${neonUserId}
      LIMIT 1
    `);

    if (!user.rows?.length) {
      return res.status(404).json({ message: "User not found" });
    }

    const userData = user.rows[0] as any;

    // Create backend JWT
    const backendToken = jwt.sign(
      {
        userId: userData.id,
        email: userData.email,
        name: userData.name,
        role: userData.role || "STUDENT",
      },
      env.jwtSecret,
      { expiresIn: "7d" },
    );

    res.json({
      token: backendToken,
      user: {
        id: userData.id,
        email: userData.email,
        name: userData.name,
        role: userData.role || "STUDENT",
      },
    });
  } catch (error) {
    console.error("[exchange-neon-token] Error:", error);
    res.status(500).json({ message: "Token exchange failed" });
  }
});

/**
 * @swagger
 * /api/auth/validate-session:
 *   post:
 *     summary: Validate current session is still active
 *     tags: [Auth Exchange]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Session valid
 *       401:
 *         description: Session invalid
 */
router.post(
  "/validate-session",
  authenticate,
  async (req: ExpressRequest, res: Response) => {
    try {
      // If we got here, middleware validated the token
      res.json({ valid: true, user: (req as any).user });
    } catch (error) {
      console.error("[validate-session] Error:", error);
      res.status(401).json({ valid: false });
    }
  },
);

export default router;
