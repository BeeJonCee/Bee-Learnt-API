import { Router } from "express";
import { createNote, listNotes } from "../controllers/notes.controller.js";
import { requireAuth } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import { lessonNoteCreateSchema } from "../shared/validators/index.js";

const notesRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Notes
 *   description: Lesson notes and reflections
 */

/**
 * @swagger
 * /api/notes:
 *   get:
 *     summary: Retrieve saved notes for the current user
 *     tags: [Notes]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of notes
 */
notesRoutes.get("/", requireAuth, listNotes);

/**
 * @swagger
 * /api/notes:
 *   post:
 *     summary: Create a new note for a lesson
 *     tags: [Notes]
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
 *         description: Note created
 */
notesRoutes.post("/", requireAuth, validateBody(lessonNoteCreateSchema), createNote);

export { notesRoutes };
