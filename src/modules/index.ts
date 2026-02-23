import { Router } from "express";
import { adminRoutes, analyticsRoutes, educationRoutes } from "./admin/index.js";
import { aiRoutes, externalRoutes, translateRoutes } from "./ai/index.js";
import { assessmentsRoutes, attemptsRoutes } from "./assessments/index.js";
import { authRoutes, authExchangeRoutes } from "./auth/index.js";
import { collaborationRoutes, messagingRoutes } from "./collaboration/index.js";
import {
  assignmentsRoutes,
  checklistsRoutes,
  curriculumRoutes,
  learningPathRoutes,
  lessonsRoutes,
  moduleAssignmentsRoutes,
  moduleUnlockRoutes,
  modulesRoutes,
  resourcesRoutes,
  rubricsRoutes,
  subjectResourcesRoutes,
  subjectsRoutes,
  userModulesRoutes,
} from "./curriculum/index.js";
import {
  badgesRoutes,
  challengesRoutes,
  leaderboardRoutes,
  pointsRoutes,
} from "./gamification/index.js";
import { announcementsRoutes, eventsRoutes, notificationsRoutes } from "./notifications/index.js";
import { nscPapersRoutes } from "./nsc-papers/index.js";
import { parentRoutes, parentStudentRoutes } from "./parents/index.js";
import { progressRoutes, progressRbacRoutes } from "./progress/index.js";
import { questionBankRoutes } from "./questions/index.js";
import { quizzesRoutes, quizzesRbacRoutes } from "./quizzes/index.js";
import { searchRoutes } from "./search/index.js";
import { studentRoutes } from "./students/index.js";
import { attendanceRoutes, notesRoutes, studyRoutes, timetableRoutes } from "./study/index.js";
import { tutorRoutes } from "./tutoring/index.js";
import { accessibilityRoutes, onboardingRoutes, preferencesRoutes } from "./users/index.js";

const router = Router();

router.use("/auth", authRoutes);
router.use("/auth", authExchangeRoutes);
router.use("/onboarding", onboardingRoutes);
router.use("/user-modules", userModulesRoutes);
router.use("/subjects", subjectsRoutes);
router.use("/modules", modulesRoutes);
router.use("/lessons", lessonsRoutes);
router.use("/assignments", assignmentsRoutes);
router.use("/rubrics", rubricsRoutes);
router.use("/resources", resourcesRoutes);
router.use("/quizzes", quizzesRoutes);
router.use("/assessments", assessmentsRoutes);
router.use("/attempts", attemptsRoutes);
router.use("/checklists", checklistsRoutes);
router.use("/badges", badgesRoutes);
router.use("/ai", aiRoutes);
router.use("/study", studyRoutes);
router.use("/announcements", announcementsRoutes);
router.use("/events", eventsRoutes);
router.use("/attendance", attendanceRoutes);
router.use("/progress", progressRoutes);
router.use("/search", searchRoutes);
router.use("/admin", adminRoutes);
router.use("/notes", notesRoutes);
router.use("/learning-path", learningPathRoutes);
router.use("/leaderboard", leaderboardRoutes);
router.use("/accessibility", accessibilityRoutes);
router.use("/external", externalRoutes);
router.use("/collaboration", collaborationRoutes);
router.use("/translate", translateRoutes);
router.use("/parent", parentRoutes);
router.use("/preferences", preferencesRoutes);
router.use("/points", pointsRoutes);
router.use("/challenges", challengesRoutes);
router.use("/student", studentRoutes);
router.use("/tutor", tutorRoutes);
router.use("/question-bank", questionBankRoutes);
router.use("/curriculum", curriculumRoutes);
router.use("/nsc-papers", nscPapersRoutes);
router.use("/messages", messagingRoutes);
router.use("/timetable", timetableRoutes);
router.use("/analytics", analyticsRoutes);
router.use("/education", educationRoutes);
router.use("/subject-resources", subjectResourcesRoutes);
router.use("/notifications", notificationsRoutes);

// RBAC-enabled routes (these routers already define their full paths, e.g. `/parents/...`)
// so we mount them at the API root to avoid double-prefixing `/api/api/...`.
router.use(parentStudentRoutes);
router.use(moduleAssignmentsRoutes);
router.use(moduleUnlockRoutes);
router.use(progressRbacRoutes);
router.use(quizzesRbacRoutes);

export { router };
export default router;
