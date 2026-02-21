import { Router } from "express";
import { requireAuth, requireRole } from "../../core/middleware/auth.js";
import { validateBody, validateQuery } from "../../core/middleware/validate.js";
import {
  nscPaperListQuerySchema,
  nscPaperCreateSchema,
  nscPaperUpdateSchema,
  nscPaperDocumentCreateSchema,
  nscPaperQuestionCreateSchema,
  nscPaperQuestionUpdateSchema,
} from "../../shared/validators/index.js";
import {
  listPapersHandler,
  getPaperHandler,
  createPaperHandler,
  updatePaperHandler,
  deletePaperHandler,
  getYearsHandler,
  getSubjectsHandler,
  listDocumentsHandler,
  createDocumentHandler,
  deleteDocumentHandler,
  listQuestionsHandler,
  createQuestionHandler,
  updateQuestionHandler,
  deleteQuestionHandler,
  importToBankHandler,
  getDiagnosticsHandler,
} from "./nsc-papers.controller.js";

const nscPapersRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: NSC Papers
 *   description: National Senior Certificate past papers, documents, and extracted questions
 */

// ============ UTILITY ENDPOINTS ============

/**
 * @swagger
 * /api/nsc-papers/years:
 *   get:
 *     summary: List available years
 *     tags: [NSC Papers]
 *     responses:
 *       200:
 *         description: List of years
 */
nscPapersRoutes.get("/years", getYearsHandler);

/**
 * @swagger
 * /api/nsc-papers/subjects:
 *   get:
 *     summary: List subjects that have papers
 *     tags: [NSC Papers]
 *     responses:
 *       200:
 *         description: List of subjects
 */
nscPapersRoutes.get("/subjects", getSubjectsHandler);

/**
 * @swagger
 * /api/nsc-papers/diagnostics:
 *   get:
 *     summary: Verify seeding completeness (Admin only)
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Diagnostics data
 */
nscPapersRoutes.get(
  "/diagnostics",
  requireAuth,
  requireRole(["ADMIN"]),
  getDiagnosticsHandler
);

// ============ PAPERS ============

/**
 * @swagger
 * /api/nsc-papers:
 *   get:
 *     summary: List NSC papers
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: year
 *         schema:
 *           type: integer
 *       - in: query
 *         name: subjectId
 *         schema:
 *           type: integer
 *       - in: query
 *         name: paperType
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of papers
 */
nscPapersRoutes.get(
  "/",
  requireAuth,
  validateQuery(nscPaperListQuerySchema),
  listPapersHandler
);

/**
 * @swagger
 * /api/nsc-papers/{id}:
 *   get:
 *     summary: Get paper by ID with documents
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Paper details with documents
 */
nscPapersRoutes.get("/:id", requireAuth, getPaperHandler);

/**
 * @swagger
 * /api/nsc-papers:
 *   post:
 *     summary: Create a paper (Admin only)
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Paper created
 */
nscPapersRoutes.post(
  "/",
  requireAuth,
  requireRole(["ADMIN"]),
  validateBody(nscPaperCreateSchema),
  createPaperHandler
);

/**
 * @swagger
 * /api/nsc-papers/{id}:
 *   put:
 *     summary: Update a paper (Admin only)
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Paper updated
 */
nscPapersRoutes.put(
  "/:id",
  requireAuth,
  requireRole(["ADMIN"]),
  validateBody(nscPaperUpdateSchema),
  updatePaperHandler
);

/**
 * @swagger
 * /api/nsc-papers/{id}:
 *   delete:
 *     summary: Delete a paper (Admin only)
 *     tags: [NSC Papers]
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
 *         description: Deleted
 */
nscPapersRoutes.delete(
  "/:id",
  requireAuth,
  requireRole(["ADMIN"]),
  deletePaperHandler
);

// ============ DOCUMENTS ============

/**
 * @swagger
 * /api/nsc-papers/{id}/documents:
 *   get:
 *     summary: List documents for a paper
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Paper documents
 */
nscPapersRoutes.get("/:id/documents", requireAuth, listDocumentsHandler);

/**
 * @swagger
 * /api/nsc-papers/{id}/documents:
 *   post:
 *     summary: Upload document for a paper (Admin only)
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       201:
 *         description: Document uploaded
 */
nscPapersRoutes.post(
  "/:id/documents",
  requireAuth,
  requireRole(["ADMIN"]),
  validateBody(nscPaperDocumentCreateSchema),
  createDocumentHandler
);

/**
 * @swagger
 * /api/nsc-papers/{id}/documents/{docId}:
 *   delete:
 *     summary: Delete a document (Admin only)
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: docId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Document deleted
 */
nscPapersRoutes.delete(
  "/:id/documents/:docId",
  requireAuth,
  requireRole(["ADMIN"]),
  deleteDocumentHandler
);

// ============ QUESTIONS ============

/**
 * @swagger
 * /api/nsc-papers/{id}/questions:
 *   get:
 *     summary: List extracted questions for a paper
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Paper questions
 */
nscPapersRoutes.get("/:id/questions", requireAuth, listQuestionsHandler);

/**
 * @swagger
 * /api/nsc-papers/{id}/questions:
 *   post:
 *     summary: Add extracted question (Admin only)
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       201:
 *         description: Question added
 */
nscPapersRoutes.post(
  "/:id/questions",
  requireAuth,
  requireRole(["ADMIN"]),
  validateBody(nscPaperQuestionCreateSchema),
  createQuestionHandler
);

/**
 * @swagger
 * /api/nsc-papers/{id}/questions/{questionId}:
 *   put:
 *     summary: Update a question (Admin only)
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: questionId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Question updated
 */
nscPapersRoutes.put(
  "/:id/questions/:questionId",
  requireAuth,
  requireRole(["ADMIN"]),
  validateBody(nscPaperQuestionUpdateSchema),
  updateQuestionHandler
);

/**
 * @swagger
 * /api/nsc-papers/{id}/questions/{questionId}:
 *   delete:
 *     summary: Delete a question (Admin only)
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: questionId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Question deleted
 */
nscPapersRoutes.delete(
  "/:id/questions/:questionId",
  requireAuth,
  requireRole(["ADMIN"]),
  deleteQuestionHandler
);

// ============ IMPORT TO QUESTION BANK ============

/**
 * @swagger
 * /api/nsc-papers/{id}/import-to-bank:
 *   post:
 *     summary: Import all extracted questions to question bank (Admin only)
 *     tags: [NSC Papers]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Questions imported
 */
nscPapersRoutes.post(
  "/:id/import-to-bank",
  requireAuth,
  requireRole(["ADMIN"]),
  importToBankHandler
);

export { nscPapersRoutes };
