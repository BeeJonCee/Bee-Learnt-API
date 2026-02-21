import { Router } from "express";
import { downloadNscDocument, downloadSubjectResource } from "../controllers/education.controller.js";
import { requireAuth } from "../core/middleware/auth.js";

const educationRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Education
 *   description: Download NSC paper documents and subject resources
 */

/**
 * @swagger
 * /api/education/nsc-documents/{documentId}/download:
 *   get:
 *     summary: Download an NSC paper document by ID
 *     tags: [Education]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: documentId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File download
 *       404:
 *         description: Document not found
 */
educationRoutes.get("/nsc-documents/:documentId/download", requireAuth, downloadNscDocument);

/**
 * @swagger
 * /api/education/resources/{resourceId}/download:
 *   get:
 *     summary: Download a subject resource by ID
 *     tags: [Education]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: resourceId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File download
 *       404:
 *         description: Resource not found
 */
educationRoutes.get("/resources/:resourceId/download", requireAuth, downloadSubjectResource);

export { educationRoutes };
