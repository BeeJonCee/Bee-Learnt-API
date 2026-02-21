import { Router } from "express";
import { requireAuth } from "../../core/middleware/auth.js";
import { translateText } from "./translate.controller.js";

const translateRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Translate
 *   description: Text translation services
 */

/**
 * @swagger
 * /api/translate:
 *   post:
 *     summary: Translate text to a target language
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
 *                 description: Text to translate
 *               targetLanguage:
 *                 type: string
 *                 description: Target language (e.g. "Zulu", "Afrikaans", "French")
 *               sourceLanguage:
 *                 type: string
 *                 description: Source language (optional, auto-detected if omitted)
 *     responses:
 *       200:
 *         description: Translated text
 *       503:
 *         description: Translation service not configured
 */
translateRoutes.post("/", requireAuth, translateText);

export { translateRoutes };
