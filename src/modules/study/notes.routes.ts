import { Router } from "express";
import { createNote, deleteNote, listNotes, updateNote } from "./notes.controller.js";
import { requireAuth } from "../../core/middleware/auth.js";
import { validateBody } from "../../core/middleware/validate.js";
import { lessonNoteCreateSchema, lessonNoteUpdateSchema } from "../../shared/validators/index.js";

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
 *     parameters:
 *       - in: query
 *         name: lessonId
 *         schema:
 *           type: integer
 *         required: true
 *         description: Filter notes by lesson
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
 *             required: [lessonId, content]
 *             properties:
 *               lessonId:
 *                 type: integer
 *               content:
 *                 type: string
 *     responses:
 *       201:
 *         description: Note created
 */
notesRoutes.post("/", requireAuth, validateBody(lessonNoteCreateSchema), createNote);

/**
 * @swagger
 * /api/notes/{id}:
 *   patch:
 *     summary: Update a note's content
 *     tags: [Notes]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [content]
 *             properties:
 *               content:
 *                 type: string
 *     responses:
 *       200:
 *         description: Updated note
 *       404:
 *         description: Note not found
 */
notesRoutes.patch("/:id", requireAuth, validateBody(lessonNoteUpdateSchema), updateNote);

/**
 * @swagger
 * /api/notes/{id}:
 *   delete:
 *     summary: Delete a note
 *     tags: [Notes]
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
 *         description: Note deleted
 *       404:
 *         description: Note not found
 */
notesRoutes.delete("/:id", requireAuth, deleteNote);

export { notesRoutes };
