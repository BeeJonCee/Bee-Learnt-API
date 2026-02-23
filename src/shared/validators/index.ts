import { z } from "zod";

// Re-export everything from sub-validator files
export * from "./questions.validators.js";
export * from "./subject-resources.validators.js";

// ─── Aliases for question bank schemas (routes use these names) ────────────────
export {
  createQuestionBankItemSchema as questionBankCreateSchema,
  updateQuestionBankItemSchema as questionBankUpdateSchema,
  questionBankFiltersSchema as questionBankListQuerySchema,
  createAssessmentSchema as assessmentCreateSchema,
  assessmentFiltersSchema as assessmentListQuerySchema,
  submitAnswerSchema as attemptAnswerSchema,
} from "./questions.validators.js";

// Question bank random query
export const questionBankRandomQuerySchema = z.object({
  count: z.coerce.number().int().positive().default(10),
  difficulty: z.enum(["easy", "medium", "hard", "adaptive"]).optional(),
  subjectId: z.coerce.number().int().positive().optional(),
  topicId: z.coerce.number().int().positive().optional(),
  moduleId: z.coerce.number().int().positive().optional(),
  type: z
    .enum([
      "multiple_choice",
      "multi_select",
      "true_false",
      "short_answer",
      "essay",
      "numeric",
      "matching",
      "ordering",
      "fill_in_blank",
    ])
    .optional(),
});

// Question bank bulk import
export const questionBankBulkImportSchema = z.object({
  questions: z.array(
    z.object({
      subjectId: z.number().int().positive(),
      type: z.enum([
        "multiple_choice",
        "multi_select",
        "true_false",
        "short_answer",
        "essay",
        "numeric",
        "matching",
        "ordering",
        "fill_in_blank",
      ]),
      questionText: z.string().min(1),
      options: z.array(z.any()).optional(),
      correctAnswer: z.any(),
      difficulty: z.enum(["easy", "medium", "hard", "adaptive"]).default("medium"),
      points: z.number().int().positive().default(1),
      explanation: z.string().optional(),
      tags: z.array(z.string()).default([]),
      topicId: z.number().int().positive().optional(),
      learningOutcomeId: z.number().int().positive().optional(),
    })
  ).min(1),
});

// ─── Auth ─────────────────────────────────────────────────────────────────────

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  twoFactorCode: z.string().optional(),
});

export const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  name: z.string().min(1).max(120).optional(),
  desiredRole: z.enum(["STUDENT", "PARENT", "TUTOR"]).optional(),
});

export const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1),
  newPassword: z.string().min(6),
});

// ─── Admin ────────────────────────────────────────────────────────────────────

export const adminUpdateUserRoleSchema = z.object({
  role: z.enum(["ADMIN", "TUTOR", "STUDENT", "PARENT"]),
});

export const adminAssignModulesSchema = z.object({
  moduleIds: z.array(z.number().int().nonnegative()),
});

// ─── Curriculum ───────────────────────────────────────────────────────────────

export const curriculumCreateSchema = z.object({
  name: z.string().min(1).max(120),
  country: z.string().min(1).max(80),
  description: z.string().optional(),
});

export const curriculumUpdateSchema = curriculumCreateSchema.partial();

export const gradeCreateSchema = z.object({
  curriculumId: z.number().int().positive(),
  level: z.number().int().min(1).max(12),
  label: z.string().min(1).max(40),
});

export const gradeUpdateSchema = gradeCreateSchema.omit({ curriculumId: true }).partial();

export const topicCreateSchema = z.object({
  subjectId: z.number().int().positive(),
  gradeId: z.number().int().positive().optional(),
  title: z.string().min(1).max(200),
  description: z.string().optional(),
  termNumber: z.number().int().min(1).max(4).optional(),
  capsReference: z.string().optional(),
  order: z.number().int().nonnegative().default(0),
  weighting: z.number().nonnegative().optional(),
});

export const topicUpdateSchema = topicCreateSchema.partial();

export const topicListQuerySchema = z.object({
  subjectId: z.coerce.number().int().positive().optional(),
  gradeId: z.coerce.number().int().positive().optional(),
  search: z.string().optional(),
});

export const learningOutcomeCreateSchema = z.object({
  topicId: z.number().int().positive(),
  description: z.string().min(1),
  code: z.string().max(40).optional(),
  bloomsLevel: z
    .enum(["remember", "understand", "apply", "analyze", "evaluate", "create"])
    .optional(),
});

export const learningOutcomeUpdateSchema = learningOutcomeCreateSchema.partial();

// ─── Subjects ─────────────────────────────────────────────────────────────────

export const subjectCreateSchema = z.object({
  name: z.string().min(1).max(120),
  description: z.string().optional(),
  minGrade: z.number().int().min(1).max(12),
  maxGrade: z.number().int().min(1).max(12),
  code: z.string().max(20).optional(),
  color: z.string().optional(),
  iconUrl: z.string().url().optional(),
});

// ─── Modules ──────────────────────────────────────────────────────────────────

export const moduleCreateSchema = z.object({
  subjectId: z.number().int().positive(),
  title: z.string().min(1).max(160),
  description: z.string().optional(),
  grade: z.number().int().min(1).max(12),
  order: z.number().int().nonnegative().default(0),
  capsTags: z.array(z.string()).default([]),
  termNumber: z.number().int().min(1).max(4).optional(),
  topicId: z.number().int().positive().optional(),
  estimatedMinutes: z.number().int().positive().optional(),
  prerequisiteModuleId: z.number().int().positive().optional(),
});

export const moduleUpdateSchema = moduleCreateSchema.partial();

export const moduleQuerySchema = z.object({
  subjectId: z.coerce.number().int().positive().optional(),
  grade: z.coerce.number().int().optional(),
  search: z.string().optional(),
});

// ─── Lessons ──────────────────────────────────────────────────────────────────

export const lessonCreateSchema = z.object({
  moduleId: z.number().int().positive(),
  title: z.string().min(1).max(160),
  content: z.string().optional(),
  type: z.enum(["video", "text", "interactive", "practice"]),
  videoUrl: z.string().url().optional(),
  diagramUrl: z.string().url().optional(),
  pdfUrl: z.string().url().optional(),
  order: z.number().int().nonnegative().default(0),
});

export const lessonUpdateSchema = lessonCreateSchema.partial();

export const lessonQuerySchema = z.object({
  moduleId: z.coerce.number().int().positive().optional(),
  type: z.enum(["video", "text", "interactive", "practice"]).optional(),
});

// ─── Resources ────────────────────────────────────────────────────────────────

export const resourceCreateSchema = z.object({
  lessonId: z.number().int().positive(),
  title: z.string().min(1).max(160),
  type: z.enum(["pdf", "video", "external_link", "worksheet"]),
  url: z.string().url(),
  tags: z.array(z.string()).default([]),
});

export const resourceQuerySchema = z.object({
  lessonId: z.coerce.number().int().positive().optional(),
  type: z.enum(["pdf", "video", "external_link", "worksheet"]).optional(),
});

// ─── Assignments ──────────────────────────────────────────────────────────────

export const assignmentQuerySchema = z.object({
  moduleId: z.coerce.number().int().positive().optional(),
  grade: z.coerce.number().int().optional(),
  status: z.enum(["pending", "submitted", "graded", "overdue"]).optional(),
});

// ─── Learning Path ────────────────────────────────────────────────────────────

export const learningPathRefreshSchema = z.object({
  force: z.boolean().default(false),
});

// ─── NSC Papers ───────────────────────────────────────────────────────────────

export const nscPaperListQuerySchema = z.object({
  year: z.coerce.number().int().positive().optional(),
  subjectId: z.coerce.number().int().positive().optional(),
  paperType: z.string().optional(),
  grade: z.coerce.number().int().optional(),
});

export const nscPaperCreateSchema = z.object({
  year: z.number().int().min(2000).max(2100),
  subjectId: z.number().int().positive(),
  paperType: z.string().min(1),
  grade: z.number().int().min(10).max(12),
  title: z.string().max(200).optional(),
  totalMarks: z.number().int().positive().optional(),
  durationMinutes: z.number().int().positive().optional(),
});

export const nscPaperUpdateSchema = nscPaperCreateSchema.partial();

export const nscPaperDocumentCreateSchema = z.object({
  title: z.string().min(1).max(200),
  fileUrl: z.string().url(),
  documentType: z.enum(["question_paper", "memo", "marking_guideline"]).optional(),
});

export const nscPaperQuestionCreateSchema = z.object({
  questionText: z.string().min(1),
  options: z.array(z.any()).optional(),
  correctAnswer: z.any(),
  topicId: z.number().int().positive().optional(),
  difficulty: z.enum(["easy", "medium", "hard"]).optional(),
  marks: z.number().int().positive().default(1),
  order: z.number().int().nonnegative().default(0),
});

export const nscPaperQuestionUpdateSchema = nscPaperQuestionCreateSchema.partial();

// ─── Study Sessions ───────────────────────────────────────────────────────────

export const studySessionCreateSchema = z.object({
  moduleId: z.number().int().positive().optional(),
  lessonId: z.number().int().positive().optional(),
  durationMinutes: z.number().int().positive().optional(),
  notes: z.string().optional(),
});

// ─── Lesson Notes ─────────────────────────────────────────────────────────────

export const lessonNoteCreateSchema = z.object({
  lessonId: z.number().int().positive(),
  content: z.string().min(1),
});

export const lessonNoteQuerySchema = z.object({
  lessonId: z.coerce.number().int().positive().optional(),
  moduleId: z.coerce.number().int().positive().optional(),
});

// ─── Timetable ────────────────────────────────────────────────────────────────

const dayOfWeek = z.enum(["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]);

export const timetableEntryCreateSchema = z.object({
  title: z.string().min(1).max(120),
  day: dayOfWeek,
  startTime: z.string().regex(/^\d{2}:\d{2}$/, "Must be HH:MM"),
  endTime: z.string().regex(/^\d{2}:\d{2}$/, "Must be HH:MM"),
  description: z.string().optional(),
  subject: z.string().optional(),
  isRecurring: z.boolean().default(true),
  color: z.string().optional(),
});

export const timetableEntryUpdateSchema = timetableEntryCreateSchema.partial();

// ─── Messaging ────────────────────────────────────────────────────────────────

export const messageCreateSchema = z.object({
  recipientId: z.string().uuid(),
  subject: z.string().min(1).max(200),
  body: z.string().min(1),
});

export const messageListQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100).default(20),
  type: z.enum(["inbox", "sent"]).optional(),
});

// ─── Announcements ────────────────────────────────────────────────────────────

export const announcementCreateSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().min(1),
  targetAudience: z.enum(["all", "students", "parents", "tutors"]).default("all"),
  priority: z.enum(["low", "medium", "high"]).default("medium"),
  expiresAt: z.string().datetime().optional(),
});

// ─── Events ───────────────────────────────────────────────────────────────────

export const eventCreateSchema = z.object({
  title: z.string().min(1).max(200),
  description: z.string().optional(),
  startDate: z.string().datetime(),
  endDate: z.string().datetime(),
  location: z.string().optional(),
  capacity: z.number().int().positive().optional(),
  type: z.enum(["academic", "social", "sports", "other"]).default("academic"),
});

// ─── AI Tutor ─────────────────────────────────────────────────────────────────

export const aiTutorSchema = z.object({
  question: z.string().min(1).max(2000),
  context: z
    .object({
      moduleId: z.number().int().positive().optional(),
      lessonId: z.number().int().positive().optional(),
      topicId: z.number().int().positive().optional(),
    })
    .optional(),
  historyLength: z.number().int().nonnegative().max(20).default(5),
});

// ─── Search ───────────────────────────────────────────────────────────────────

export const searchQuerySchema = z.object({
  query: z.string().min(2).max(200),
  type: z.enum(["all", "modules", "lessons", "topics", "users"]).optional(),
  limit: z.coerce.number().int().positive().max(50).default(20),
});

// ─── Accessibility ────────────────────────────────────────────────────────────

export const accessibilityUpdateSchema = z.object({
  fontSize: z.enum(["small", "medium", "large", "x-large"]).optional(),
  highContrast: z.boolean().optional(),
  dyslexicFont: z.boolean().optional(),
  screenReader: z.boolean().optional(),
  keyboardNavigation: z.boolean().optional(),
  captions: z.boolean().optional(),
  reduceMotion: z.boolean().optional(),
});

// ─── Onboarding ───────────────────────────────────────────────────────────────

export const onboardingSelectSchema = z.object({
  moduleId: z.number().int().positive(),
});

export const onboardingRequestCodeSchema = z.object({
  reason: z.string().optional(),
  comments: z.string().optional(),
});

// ─── Progress ─────────────────────────────────────────────────────────────────

export const progressQuerySchema = z.object({
  lessonId: z.coerce.number().int().positive().optional(),
  moduleId: z.coerce.number().int().positive().optional(),
});

export const progressUpdateSchema = z.object({
  lessonId: z.number().int().positive().optional(),
  moduleId: z.number().int().positive().optional(),
  completed: z.boolean(),
  timeSpentMinutes: z.number().int().nonnegative().optional(),
});

// ─── Quizzes (legacy quiz system) ─────────────────────────────────────────────

export const quizGenerateSchema = z.object({
  subjectId: z.number().int().positive(),
  topicId: z.number().int().positive().optional(),
  difficulty: z.enum(["easy", "medium", "hard"]).optional(),
  questionCount: z.number().int().min(1).max(50).default(10),
  timeLimit: z.number().int().positive().optional(),
});

export const quizSubmitSchema = z.object({
  answers: z.array(
    z.object({
      questionId: z.number().int().positive(),
      selectedOption: z.string().or(z.number()).or(z.boolean()),
    })
  ),
});

export const quizQuerySchema = z.object({
  subjectId: z.coerce.number().int().positive().optional(),
  topicId: z.coerce.number().int().positive().optional(),
  status: z.enum(["active", "archived"]).optional(),
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(50).default(20),
});

export const quizUpdateSchema = z.object({
  title: z.string().min(1).max(200).optional(),
  description: z.string().optional(),
  isActive: z.boolean().optional(),
  timeLimit: z.number().int().positive().optional(),
});

export const quizCheckSchema = z.object({
  quizId: z.number().int().positive(),
  answers: z.array(
    z.object({
      questionId: z.number().int().positive(),
      selectedOption: z.union([z.string(), z.number(), z.boolean()]),
    })
  ),
});
