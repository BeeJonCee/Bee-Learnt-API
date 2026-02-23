import { Router } from "express";
import { requireAuth, requireRole } from "../../core/middleware/auth.js";
import {
  list,
  create,
  getById,
  update,
  remove,
  publish,
  close,
  startMarking,
  release,
  createSection,
  updateSectionHandler,
  deleteSectionHandler,
  addQuestion,
  patchQuestion,
  removeQuestion,
  assign,
  getAssignments,
  deleteAssignment,
  getSubmissions,
  getSubmissionById,
  markAnswerHandler,
  finalizeMarkingHandler,
  myPapers,
  startPaperHandler,
  getPaperResultHandler,
} from "./papers.controller.js";

const papersRoutes = Router();

// ── Student routes ────────────────────────────────────────────────────────────

papersRoutes.get("/my-papers", requireAuth, requireRole(["STUDENT"]), myPapers);
papersRoutes.post("/:id/start", requireAuth, requireRole(["STUDENT"]), startPaperHandler);
papersRoutes.get("/:id/result", requireAuth, requireRole(["STUDENT"]), getPaperResultHandler);

// ── Admin/Tutor: paper CRUD ───────────────────────────────────────────────────

papersRoutes.get("/", requireAuth, requireRole(["ADMIN", "TUTOR"]), list);
papersRoutes.post("/", requireAuth, requireRole(["ADMIN"]), create);
papersRoutes.get("/:id", requireAuth, requireRole(["ADMIN", "TUTOR"]), getById);
papersRoutes.put("/:id", requireAuth, requireRole(["ADMIN"]), update);
papersRoutes.delete("/:id", requireAuth, requireRole(["ADMIN"]), remove);

// ── State transitions ─────────────────────────────────────────────────────────

papersRoutes.post("/:id/publish", requireAuth, requireRole(["ADMIN"]), publish);
papersRoutes.post("/:id/close", requireAuth, requireRole(["ADMIN"]), close);
papersRoutes.post("/:id/start-marking", requireAuth, requireRole(["ADMIN"]), startMarking);
papersRoutes.post("/:id/release", requireAuth, requireRole(["ADMIN"]), release);

// ── Sections ──────────────────────────────────────────────────────────────────

papersRoutes.post("/:id/sections", requireAuth, requireRole(["ADMIN"]), createSection);
papersRoutes.put("/:id/sections/:sectionId", requireAuth, requireRole(["ADMIN"]), updateSectionHandler);
papersRoutes.delete("/:id/sections/:sectionId", requireAuth, requireRole(["ADMIN"]), deleteSectionHandler);

// ── Questions ─────────────────────────────────────────────────────────────────

papersRoutes.post("/:id/sections/:sectionId/questions", requireAuth, requireRole(["ADMIN"]), addQuestion);
papersRoutes.patch("/:id/sections/:sectionId/questions/:pqId", requireAuth, requireRole(["ADMIN"]), patchQuestion);
papersRoutes.delete("/:id/sections/:sectionId/questions/:pqId", requireAuth, requireRole(["ADMIN"]), removeQuestion);

// ── Assignments ───────────────────────────────────────────────────────────────

papersRoutes.post("/:id/assignments", requireAuth, requireRole(["ADMIN"]), assign);
papersRoutes.get("/:id/assignments", requireAuth, requireRole(["ADMIN", "TUTOR"]), getAssignments);
papersRoutes.delete("/:id/assignments/:assignmentId", requireAuth, requireRole(["ADMIN"]), deleteAssignment);

// ── Submissions / Marking ─────────────────────────────────────────────────────

papersRoutes.get("/:id/submissions", requireAuth, requireRole(["ADMIN", "TUTOR"]), getSubmissions);
papersRoutes.get("/:id/submissions/:attemptId", requireAuth, requireRole(["ADMIN", "TUTOR"]), getSubmissionById);
papersRoutes.patch(
  "/:id/submissions/:attemptId/answers/:answerId",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  markAnswerHandler,
);
papersRoutes.post(
  "/:id/submissions/:attemptId/finalize-marking",
  requireAuth,
  requireRole(["ADMIN", "TUTOR"]),
  finalizeMarkingHandler,
);

export { papersRoutes };
