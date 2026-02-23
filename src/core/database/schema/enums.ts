import { pgEnum } from "drizzle-orm/pg-core";

// ── USER & AUTH ─────────────────────────────
export const roleEnum = pgEnum("role", ["STUDENT", "PARENT", "ADMIN", "TUTOR"]);

// ── CONTENT & LESSONS ───────────────────────
export const lessonTypeEnum = pgEnum("lesson_type", ["text", "video", "diagram", "pdf"]);
export const resourceTypeEnum = pgEnum("resource_type", ["pdf", "link", "video", "diagram"]);
export const contentAudienceEnum = pgEnum("content_audience", ["ALL", "STUDENT", "PARENT", "ADMIN", "TUTOR"]);

// ── MODULE & ACCESS ─────────────────────────
export const moduleAccessStatusEnum = pgEnum("module_access_status", ["pending", "unlocked"]);
export const moduleAssignmentStatusEnum = pgEnum("module_assignment_status", [
  "assigned",
  "in_progress",
  "completed",
  "overdue",
]);

// ── QUIZ & QUESTION ─────────────────────────
export const quizDifficultyEnum = pgEnum("quiz_difficulty", ["easy", "medium", "hard", "adaptive"]);
export const quizTypeEnum = pgEnum("quiz_question_type", [
  "multiple_choice",
  "multi_select",
  "true_false",
  "short_answer",
  "essay",
  "numeric",
  "matching",
  "ordering",
  "fill_in_blank",
]);

// ── ASSIGNMENT ──────────────────────────────
export const assignmentPriorityEnum = pgEnum("assignment_priority", ["low", "medium", "high"]);
export const assignmentStatusEnum = pgEnum("assignment_status", [
  "todo",
  "in_progress",
  "submitted",
  "graded",
]);

// ── PROGRESS & LEARNING ─────────────────────
export const learningPaceEnum = pgEnum("learning_pace", ["slow", "steady", "fast"]);
export const learningPathStatusEnum = pgEnum("learning_path_status", [
  "active",
  "completed",
  "dismissed",
]);

// ── COLLABORATION ───────────────────────────
export const collaborationRoomTypeEnum = pgEnum("collaboration_room_type", [
  "classroom",
  "project",
  "discussion",
  "breakout",
]);

// ── GAMIFICATION ────────────────────────────
export const badgeRuleEnum = pgEnum("badge_rule", [
  "lesson_streak",
  "quiz_mastery",
  "assignment_finisher",
  "study_time",
]);

export const studyGoalStatusEnum = pgEnum("study_goal_status", [
  "active",
  "completed",
  "abandoned",
  "overdue",
]);

export const studyGoalPriorityEnum = pgEnum("study_goal_priority", [
  "low",
  "medium",
  "high",
]);

export const challengeTypeEnum = pgEnum("challenge_type", [
  "daily",
  "weekly",
  "special",
]);

export const challengeStatusEnum = pgEnum("challenge_status", [
  "active",
  "completed",
  "expired",
]);

// ── SYSTEM & ADMIN ──────────────────────────
export const attendanceStatusEnum = pgEnum("attendance_status", [
  "present",
  "absent",
  "late",
  "excused",
]);

// ── QUESTION BANK & ASSESSMENT ──────────────
export const questionBankSourceEnum = pgEnum("qb_source", [
  "manual",
  "nsc_past_paper",
  "exemplar",
  "textbook",
  "ai_generated",
  "imported",
]);

export const assessmentTypeEnum = pgEnum("assessment_type", [
  "quiz",
  "test",
  "exam",
  "practice",
  "nsc_simulation",
  "diagnostic",
]);

export const assessmentStatusEnum = pgEnum("assessment_status", [
  "draft",
  "published",
  "archived",
]);

export const attemptStatusEnum = pgEnum("attempt_status", [
  "in_progress",
  "submitted",
  "timed_out",
  "graded",
  "reviewed",
]);

// ── TUTORING ────────────────────────────────
export const tutoringSessionStatusEnum = pgEnum("tutoring_session_status", [
  "scheduled",
  "in_progress",
  "completed",
  "cancelled",
  "no_show",
]);

// ── NSC PAPERS ──────────────────────────────
export const examSessionEnum = pgEnum("exam_session", [
  "november",
  "may_june",
  "february_march",
  "supplementary",
  "exemplar",
]);

export const paperDocTypeEnum = pgEnum("paper_doc_type", [
  "question_paper",
  "memorandum",
  "marking_guideline",
  "answer_book",
  "data_files",
  "addendum",
  "formula_sheet",
]);

// ── TIMETABLE ───────────────────────────────
export const dayOfWeekEnum = pgEnum("day_of_week", [
  "monday",
  "tuesday",
  "wednesday",
  "thursday",
  "friday",
  "saturday",
  "sunday",
]);

// ── SUBJECT RESOURCES ───────────────────────
export const subjectResourceTypeEnum = pgEnum("subject_resource_type", [
  "textbook",
  "teacher_guide",
  "practical_guide",
  "pat_document",
  "caps_document",
  "learner_data",
  "revision_guide",
  "workbook",
  "tutoring_guide",
]);
