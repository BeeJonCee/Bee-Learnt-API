import { Router } from "express";
import { requireAuth } from "../core/middleware/auth.js";
import { validateBody } from "../core/middleware/validate.js";
import {
  timetableEntryCreateSchema,
  timetableEntryUpdateSchema,
} from "../shared/validators/index.js";
import {
  listEntriesHandler,
  getEntryHandler,
  getStudentEntriesHandler,
  createEntryHandler,
  updateEntryHandler,
  deleteEntryHandler,
  getEntriesByDayHandler,
} from "../controllers/timetable.controller.js";
import { guard } from "../lib/rbac/guard.js";

const timetableRoutes = Router();

/**
 * @swagger
 * tags:
 *   name: Timetable
 *   description: Personal timetable management
 */

timetableRoutes.use(requireAuth);

/**
 * @swagger
 * /api/timetable:
 *   get:
 *     summary: Get all timetable entries for current user
 *     tags: [Timetable]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Timetable entries
 */
timetableRoutes.get("/", listEntriesHandler);

/**
 * @swagger
 * /api/timetable/day/{day}:
 *   get:
 *     summary: Get entries for a specific day
 *     tags: [Timetable]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: day
 *         required: true
 *         schema:
 *           type: string
 *           enum: [monday, tuesday, wednesday, thursday, friday, saturday, sunday]
 *     responses:
 *       200:
 *         description: Entries for the day
 */
timetableRoutes.get("/day/:day", getEntriesByDayHandler);

/**
 * @swagger
 * /api/timetable/student/{studentId}:
 *   get:
 *     summary: Get timetable entries for a specific student (parent/admin access)
 *     tags: [Timetable]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: studentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Student timetable entries
 */
timetableRoutes.get(
  "/student/:studentId",
  guard({
    roles: ["PARENT", "ADMIN"],
    ownership: {
      type: "student",
      idParam: "studentId",
      allowParent: true,
    },
  }),
  getStudentEntriesHandler
);

/**
 * @swagger
 * /api/timetable/{id}:
 *   get:
 *     summary: Get a single timetable entry
 *     tags: [Timetable]
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
 *         description: Entry details
 */
timetableRoutes.get("/:id", getEntryHandler);

/**
 * @swagger
 * /api/timetable:
 *   post:
 *     summary: Create a new timetable entry
 *     tags: [Timetable]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       201:
 *         description: Entry created
 */
timetableRoutes.post(
  "/",
  validateBody(timetableEntryCreateSchema),
  createEntryHandler
);

/**
 * @swagger
 * /api/timetable/{id}:
 *   put:
 *     summary: Update a timetable entry
 *     tags: [Timetable]
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
 *         description: Entry updated
 */
timetableRoutes.put(
  "/:id",
  validateBody(timetableEntryUpdateSchema),
  updateEntryHandler
);

/**
 * @swagger
 * /api/timetable/{id}:
 *   delete:
 *     summary: Delete a timetable entry
 *     tags: [Timetable]
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
timetableRoutes.delete("/:id", deleteEntryHandler);

export { timetableRoutes };
