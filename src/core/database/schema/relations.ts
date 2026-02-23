import { relations } from "drizzle-orm";

// Users & Auth
import {
  roles,
  users,
  parentStudentLinks,
  studentProfiles,
  parentProfiles,
} from "./users.schema.js";

// Content
import { subjects, modules, lessons } from "./content.schema.js";

// Curriculum
import { curricula, grades, topics } from "./curriculum.schema.js";

// Legacy Quizzes
import {
  quizzes,
  quizQuestions,
  quizAttempts,
  quizAnswers,
} from "./quiz-legacy.schema.js";

// Assessments
import {
  assessments,
  assessmentSections,
  assessmentQuestions,
  assessmentAttempts,
  attemptAnswers,
} from "./assessments.schema.js";

// NSC Papers
import {
  nscPapers,
  nscPaperDocuments,
  nscPaperQuestions,
} from "./nsc-papers.schema.js";

// Question Bank
import { questionBankItems } from "./questions.schema.js";

// Progress
import { progressTracking } from "./progress.schema.js";

// System
import { auditLogs } from "./system.schema.js";

// Unlock
import {
  moduleAssignments,
  dailyModuleTokens,
  tokenAttempts,
} from "./unlock.schema.js";

// Social
import { directMessages } from "./social.schema.js";

// Tutoring
import { sessionFeedback } from "./tutoring.schema.js";

// Gamification
import { studySessions } from "./gamification.schema.js";

// ══════════════════════════════════════════
// RELATION DEFINITIONS
// ══════════════════════════════════════════

// ── ROLES ───────────────────────────────────

export const rolesRelations = relations(roles, ({ many }) => ({
  users: many(users),
}));

// ── USERS ───────────────────────────────────

export const usersRelations = relations(users, ({ one, many }) => ({
  studentProfile: one(studentProfiles),
  parentProfile: one(parentProfiles),
  role: one(roles, {
    fields: [users.roleId],
    references: [roles.id],
  }),

  parentLinks: many(parentStudentLinks, { relationName: "parentLink" }),
  studentLinks: many(parentStudentLinks, { relationName: "studentLink" }),

  moduleAssignmentsAsStudent: many(moduleAssignments, {
    relationName: "moduleAssignmentStudent",
  }),
  moduleAssignmentsAsAssigner: many(moduleAssignments, {
    relationName: "moduleAssignmentAssigner",
  }),

  assessmentAttemptsAsUser: many(assessmentAttempts, {
    relationName: "assessmentAttemptUser",
  }),
  assessmentAttemptsAsGrader: many(assessmentAttempts, {
    relationName: "assessmentAttemptGrader",
  }),

  sentMessages: many(directMessages, { relationName: "sentMessage" }),
  receivedMessages: many(directMessages, { relationName: "receivedMessage" }),

  feedbackGiven: many(sessionFeedback, { relationName: "feedbackGiven" }),
  feedbackReceived: many(sessionFeedback, { relationName: "feedbackReceived" }),
}));

// ── STUDENT PROFILES ────────────────────────

export const studentProfilesRelations = relations(
  studentProfiles,
  ({ one }) => ({
    user: one(users, {
      fields: [studentProfiles.userId],
      references: [users.id],
    }),
  }),
);

// ── PARENT PROFILES ─────────────────────────

export const parentProfilesRelations = relations(
  parentProfiles,
  ({ one }) => ({
    user: one(users, {
      fields: [parentProfiles.userId],
      references: [users.id],
    }),
  }),
);

// ── PARENT-STUDENT LINKS ────────────────────

export const parentStudentLinksRelations = relations(
  parentStudentLinks,
  ({ one }) => ({
    parent: one(users, {
      fields: [parentStudentLinks.parentId],
      references: [users.id],
      relationName: "parentLink",
    }),
    student: one(users, {
      fields: [parentStudentLinks.studentId],
      references: [users.id],
      relationName: "studentLink",
    }),
  }),
);

// ── SUBJECTS ────────────────────────────────

export const subjectsRelations = relations(subjects, ({ many }) => ({
  modules: many(modules),
}));

// ── MODULES ─────────────────────────────────

export const modulesRelations = relations(modules, ({ one, many }) => ({
  subject: one(subjects, {
    fields: [modules.subjectId],
    references: [subjects.id],
  }),
  lessons: many(lessons),
  quizzes: many(quizzes),
}));

// ── LESSONS ─────────────────────────────────

export const lessonsRelations = relations(lessons, ({ one }) => ({
  module: one(modules, {
    fields: [lessons.moduleId],
    references: [modules.id],
  }),
}));

// ── QUIZZES ─────────────────────────────────

export const quizzesRelations = relations(quizzes, ({ one, many }) => ({
  module: one(modules, {
    fields: [quizzes.moduleId],
    references: [modules.id],
  }),
  questions: many(quizQuestions),
  attempts: many(quizAttempts),
}));

// ── QUIZ QUESTIONS ──────────────────────────

export const quizQuestionsRelations = relations(quizQuestions, ({ one }) => ({
  quiz: one(quizzes, {
    fields: [quizQuestions.quizId],
    references: [quizzes.id],
  }),
}));

// ── QUIZ ATTEMPTS ───────────────────────────

export const quizAttemptsRelations = relations(
  quizAttempts,
  ({ one, many }) => ({
    quiz: one(quizzes, {
      fields: [quizAttempts.quizId],
      references: [quizzes.id],
    }),
    user: one(users, {
      fields: [quizAttempts.userId],
      references: [users.id],
    }),
    answers: many(quizAnswers),
  }),
);

// ── QUIZ ANSWERS ────────────────────────────

export const quizAnswersRelations = relations(quizAnswers, ({ one }) => ({
  attempt: one(quizAttempts, {
    fields: [quizAnswers.attemptId],
    references: [quizAttempts.id],
  }),
  question: one(quizQuestions, {
    fields: [quizAnswers.questionId],
    references: [quizQuestions.id],
  }),
}));

// ── GRADES ──────────────────────────────────

export const gradesRelations = relations(grades, ({ one }) => ({
  curriculum: one(curricula, {
    fields: [grades.curriculumId],
    references: [curricula.id],
  }),
}));

// ── TOPICS ──────────────────────────────────

export const topicsRelations = relations(topics, ({ one }) => ({
  subject: one(subjects, {
    fields: [topics.subjectId],
    references: [subjects.id],
  }),
  grade: one(grades, {
    fields: [topics.gradeId],
    references: [grades.id],
  }),
}));

// ── QUESTION BANK ITEMS ─────────────────────

export const questionBankItemsRelations = relations(
  questionBankItems,
  ({ one }) => ({
    subject: one(subjects, {
      fields: [questionBankItems.subjectId],
      references: [subjects.id],
    }),
    module: one(modules, {
      fields: [questionBankItems.moduleId],
      references: [modules.id],
    }),
  }),
);

// ── ASSESSMENTS ─────────────────────────────

export const assessmentsRelations = relations(
  assessments,
  ({ one, many }) => ({
    subject: one(subjects, {
      fields: [assessments.subjectId],
      references: [subjects.id],
    }),
    sections: many(assessmentSections),
    questions: many(assessmentQuestions),
    attempts: many(assessmentAttempts),
  }),
);

// ── ASSESSMENT SECTIONS ─────────────────────

export const assessmentSectionsRelations = relations(
  assessmentSections,
  ({ one, many }) => ({
    assessment: one(assessments, {
      fields: [assessmentSections.assessmentId],
      references: [assessments.id],
    }),
    questions: many(assessmentQuestions),
  }),
);

// ── ASSESSMENT QUESTIONS ────────────────────

export const assessmentQuestionsRelations = relations(
  assessmentQuestions,
  ({ one }) => ({
    assessment: one(assessments, {
      fields: [assessmentQuestions.assessmentId],
      references: [assessments.id],
    }),
    section: one(assessmentSections, {
      fields: [assessmentQuestions.sectionId],
      references: [assessmentSections.id],
    }),
    questionBankItem: one(questionBankItems, {
      fields: [assessmentQuestions.questionBankItemId],
      references: [questionBankItems.id],
    }),
  }),
);

// ── ASSESSMENT ATTEMPTS ─────────────────────

export const assessmentAttemptsRelations = relations(
  assessmentAttempts,
  ({ one, many }) => ({
    assessment: one(assessments, {
      fields: [assessmentAttempts.assessmentId],
      references: [assessments.id],
    }),
    user: one(users, {
      fields: [assessmentAttempts.userId],
      references: [users.id],
      relationName: "assessmentAttemptUser",
    }),
    grader: one(users, {
      fields: [assessmentAttempts.gradedBy],
      references: [users.id],
      relationName: "assessmentAttemptGrader",
    }),
    answers: many(attemptAnswers),
  }),
);

// ── ATTEMPT ANSWERS ─────────────────────────

export const attemptAnswersRelations = relations(attemptAnswers, ({ one }) => ({
  attempt: one(assessmentAttempts, {
    fields: [attemptAnswers.attemptId],
    references: [assessmentAttempts.id],
  }),
  assessmentQuestion: one(assessmentQuestions, {
    fields: [attemptAnswers.assessmentQuestionId],
    references: [assessmentQuestions.id],
  }),
  questionBankItem: one(questionBankItems, {
    fields: [attemptAnswers.questionBankItemId],
    references: [questionBankItems.id],
  }),
}));

// ── NSC PAPERS ──────────────────────────────

export const nscPapersRelations = relations(nscPapers, ({ one, many }) => ({
  subject: one(subjects, {
    fields: [nscPapers.subjectId],
    references: [subjects.id],
  }),
  grade: one(grades, {
    fields: [nscPapers.gradeId],
    references: [grades.id],
  }),
  documents: many(nscPaperDocuments),
  questions: many(nscPaperQuestions),
}));

export const nscPaperDocumentsRelations = relations(
  nscPaperDocuments,
  ({ one }) => ({
    paper: one(nscPapers, {
      fields: [nscPaperDocuments.nscPaperId],
      references: [nscPapers.id],
    }),
  }),
);

export const nscPaperQuestionsRelations = relations(
  nscPaperQuestions,
  ({ one }) => ({
    paper: one(nscPapers, {
      fields: [nscPaperQuestions.nscPaperId],
      references: [nscPapers.id],
    }),
  }),
);

// ── PROGRESS TRACKING ───────────────────────

export const progressTrackingRelations = relations(
  progressTracking,
  ({ one }) => ({
    user: one(users, {
      fields: [progressTracking.userId],
      references: [users.id],
    }),
    lesson: one(lessons, {
      fields: [progressTracking.lessonId],
      references: [lessons.id],
    }),
    module: one(modules, {
      fields: [progressTracking.moduleId],
      references: [modules.id],
    }),
  }),
);

// ── STUDY SESSIONS ──────────────────────────

export const studySessionsRelations = relations(studySessions, ({ one }) => ({
  user: one(users, {
    fields: [studySessions.userId],
    references: [users.id],
  }),
}));

// ── AUDIT LOGS ──────────────────────────────

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
  actor: one(users, {
    fields: [auditLogs.actorId],
    references: [users.id],
  }),
}));

// ── MODULE ASSIGNMENTS ──────────────────────

export const moduleAssignmentsRelations = relations(
  moduleAssignments,
  ({ one }) => ({
    module: one(modules, {
      fields: [moduleAssignments.moduleId],
      references: [modules.id],
    }),
    student: one(users, {
      fields: [moduleAssignments.studentId],
      references: [users.id],
      relationName: "moduleAssignmentStudent",
    }),
    assigner: one(users, {
      fields: [moduleAssignments.assignedBy],
      references: [users.id],
      relationName: "moduleAssignmentAssigner",
    }),
  }),
);

// ── DAILY MODULE TOKENS ─────────────────────

export const dailyModuleTokensRelations = relations(
  dailyModuleTokens,
  ({ one }) => ({
    module: one(modules, {
      fields: [dailyModuleTokens.moduleId],
      references: [modules.id],
    }),
  }),
);

// ── TOKEN ATTEMPTS ──────────────────────────

export const tokenAttemptsRelations = relations(tokenAttempts, ({ one }) => ({
  student: one(users, {
    fields: [tokenAttempts.studentId],
    references: [users.id],
  }),
  module: one(modules, {
    fields: [tokenAttempts.moduleId],
    references: [modules.id],
  }),
}));

// ── DIRECT MESSAGES ─────────────────────────

export const directMessagesRelations = relations(
  directMessages,
  ({ one }) => ({
    sender: one(users, {
      fields: [directMessages.senderId],
      references: [users.id],
      relationName: "sentMessage",
    }),
    recipient: one(users, {
      fields: [directMessages.recipientId],
      references: [users.id],
      relationName: "receivedMessage",
    }),
  }),
);

// ── SESSION FEEDBACK ────────────────────────

export const sessionFeedbackRelations = relations(
  sessionFeedback,
  ({ one }) => ({
    fromUser: one(users, {
      fields: [sessionFeedback.fromUserId],
      references: [users.id],
      relationName: "feedbackGiven",
    }),
    toUser: one(users, {
      fields: [sessionFeedback.toUserId],
      references: [users.id],
      relationName: "feedbackReceived",
    }),
  }),
);
