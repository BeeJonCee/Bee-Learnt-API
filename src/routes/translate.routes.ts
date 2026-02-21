import { Router } from "express";
import { translateText } from "../controllers/translate.controller.js";
import { requireAuth } from "../core/middleware/auth.js";

const translateRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Translate
 *   description: Text translation service
 */

/**
 * @swagger
 * /api/translate:
 *   post:
 *     summary: Translate text
 *     tags: [Translate]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [text, targetLanguage]
 *             properties:
 *               text:
 *                 type: string
 *               targetLanguage:
 *                 type: string
 *               sourceLanguage:
 *                 type: string
 *     responses:
 *       200:
 *         description: Translated text
 */
translateRoutes.post("/", requireAuth, translateText);

export { translateRoutes };
