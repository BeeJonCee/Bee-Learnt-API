import { z } from "zod";

export const moduleCreateSchema = z.object({
  subjectId: z.number().int().positive(),
  title: z.string().min(3),
  description: z.string().optional(),
  grade: z.number().int().min(9).max(12),
  order: z.number().int().min(1),
  capsTags: z.array(z.string()).default([]),
});

export const moduleUpdateSchema = moduleCreateSchema.partial();

export const moduleQuerySchema = z.object({
  subjectId: z.number().int().positive().optional(),
  grade: z.number().int().min(9).max(12).optional(),
});

export const subjectCreateSchema = z.object({
  name: z.string().min(3),
  description: z.string().optional(),
  minGrade: z.number().int().min(9).max(12),
  maxGrade: z.number().int().min(9).max(12),
});

export const lessonCreateSchema = z.object({
  moduleId: z.number().int().positive(),
  title: z.string().min(3),
  content: z.string().optional(),
  type: z.enum(["text", "video", "diagram", "pdf"]),
  videoUrl: z.string().url().optional().nullable(),
  diagramUrl: z.string().url().optional().nullable(),
  pdfUrl: z.string().url().optional().nullable(),
  order: z.number().int().min(1),
});

export const lessonUpdateSchema = lessonCreateSchema.partial();

export const lessonQuerySchema = z.object({
  moduleId: z.number().int().positive().optional(),
});

export const resourceCreateSchema = z.object({
  lessonId: z.number().int().positive(),
  title: z.string().min(3),
  type: z.enum(["pdf", "link", "video", "diagram"]),
  url: z.string().url(),
  tags: z.array(z.string()).default([]),
});

export const resourceQuerySchema = z.object({
  lessonId: z.number().int().positive().optional(),
});

export const assignmentCreateSchema = z.object({
  moduleId: z.number().int().positive(),
  lessonId: z.number().int().positive().optional(),
  title: z.string().min(3),
  description: z.string().optional(),
  dueDate: z.string().datetime(),
  priority: z.enum(["low", "medium", "high"]).default("medium"),
  status: z.enum(["todo", "in_progress", "submitted", "graded"]).default("todo"),
  grade: z.number().int().min(9).max(12),
});

export const assignmentUpdateSchema = z.object({
  title: z.string().min(3).optional(),
  description: z.string().optional(),
  dueDate: z.string().datetime().optional(),
  priority: z.enum(["low", "medium", "high"]).optional(),
  status: z.enum(["todo", "in_progress", "submitted", "graded"]).optional(),
  grade: z.number().int().min(9).max(12).optional(),
});

export const assignmentQuerySchema = z.object({
  moduleId: z.number().int().positive().optional(),
  grade: z.number().int().min(9).max(12).optional(),
});

export const quizGenerateSchema = z.object({
  subjectId: z.number().int().positive(),
  moduleId: z.number().int().positive(),
  topic: z.string().min(3),
  grade: z.number().int().min(9).max(12),
  capsTags: z.array(z.string()).default([]),
  difficulty: z.enum(["easy", "medium", "hard", "adaptive"]).default("medium"),
  performance: z
    .object({
      averageScore: z.number().min(0).max(100).optional(),
      recentMistakes: z.array(z.string()).optional(),
    })
    .optional(),
});

export const quizQuerySchema = z.object({
  moduleId: z.number().int().positive().optional(),
});

export const quizSubmitSchema = z.object({
  quizId: z.number().int().positive(),
  answers: z.array(
    z.object({
      questionId: z.number().int().positive(),
      answer: z.string().min(1),
    })
  ),
});

export const quizCheckSchema = z.object({
  questionId: z.number().int().positive(),
  answer: z.string().min(1),
});

export const studySessionCreateSchema = z.object({
  startedAt: z.string().datetime(),
  endedAt: z.string().datetime().optional(),
  durationMinutes: z.number().int().min(1),
});

export const progressUpdateSchema = z.object({
  lessonId: z.number().int().positive().optional(),
  moduleId: z.number().int().positive().optional(),
  completed: z.boolean().optional(),
  timeSpentMinutes: z.number().int().min(0).optional(),
});

export const progressQuerySchema = z.object({
  lessonId: z.number().int().positive().optional(),
  moduleId: z.number().int().positive().optional(),
});

export const checklistProgressSchema = z.object({
  itemId: z.number().int().positive(),
  completed: z.boolean(),
});

export const learningPathRefreshSchema = z.object({
  goal: z.string().min(2).optional(),
  focusTags: z.array(z.string()).optional(),
});

export const onboardingSelectSchema = z.object({
  moduleId: z.number().int().positive(),
  code: z.string().min(3),
});

export const lessonNoteCreateSchema = z.object({
  lessonId: z.number().int().positive(),
  content: z.string().min(3).max(2000),
});

export const lessonNoteQuerySchema = z.object({
  lessonId: z.number().int().positive(),
});

export const accessibilityUpdateSchema = z.object({
  textScale: z.number().int().min(80).max(150).optional(),
  enableNarration: z.boolean().optional(),
  highContrast: z.boolean().optional(),
  language: z.string().min(2).max(12).optional(),
  translationEnabled: z.boolean().optional(),
});

export const aiTutorSchema = z.object({
  messages: z.array(
    z.object({
      role: z.enum(["user", "assistant"]),
      content: z.string().min(1),
    })
  ),
});

export const searchQuerySchema = z.object({
  query: z.string().min(2),
});

export const registerSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(6),
  role: z.enum(["STUDENT", "PARENT"]).default("STUDENT"),
});

export const announcementCreateSchema = z.object({
  title: z.string().min(3),
  body: z.string().min(10),
  audience: z.enum(["ALL", "STUDENT", "PARENT", "ADMIN"]).default("ALL"),
  pinned: z.boolean().optional(),
  publishedAt: z.string().datetime().optional(),
});

export const eventCreateSchema = z.object({
  title: z.string().min(3),
  description: z.string().min(5),
  startAt: z.string().datetime(),
  endAt: z.string().datetime().optional().nullable(),
  allDay: z.boolean().optional(),
  location: z.string().min(2).optional().nullable(),
  audience: z.enum(["ALL", "STUDENT", "PARENT", "ADMIN"]).default("ALL"),
});

export const attendanceCreateSchema = z.object({
  studentId: z.string().uuid(),
  date: z.string().datetime(),
  status: z.enum(["present", "absent", "late", "excused"]),
  notes: z.string().optional().nullable(),
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

export const emailVerificationSendSchema = z.object({
  email: z.string().email(),
});

export const emailVerificationConfirmSchema = z.object({
  email: z.string().email(),
  code: z.string().min(4).max(32),
});

export const adminAssignModulesSchema = z.object({
  moduleIds: z.array(z.number().int().positive()),
});

export const adminUpdateUserRoleSchema = z.object({
  role: z.enum(["STUDENT", "PARENT", "ADMIN", "TUTOR"]),
});

// ============ ASSESSMENTS ============

export const assessmentListQuerySchema = z.object({
  subjectId: z.coerce.number().int().positive().optional(),
  moduleId: z.coerce.number().int().positive().optional(),
  grade: z.coerce.number().int().min(9).max(12).optional(),
  type: z
    .enum(["quiz", "test", "exam", "practice", "nsc_simulation", "diagnostic"])
    .optional(),
  status: z.enum(["draft", "published", "archived"]).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

export const assessmentCreateSchema = z.object({
  title: z.string().min(3),
  description: z.string().optional(),
  type: z.enum(["quiz", "test", "exam", "practice", "nsc_simulation", "diagnostic"]),
  status: z.enum(["draft", "published", "archived"]).optional(),
  subjectId: z.number().int().positive(),
  grade: z.number().int().min(9).max(12).optional(),
  moduleId: z.number().int().positive().optional(),
  timeLimitMinutes: z.number().int().positive().optional(),
  maxAttempts: z.number().int().positive().optional(),
  shuffleQuestions: z.boolean().optional(),
  shuffleOptions: z.boolean().optional(),
  showResultsImmediately: z.boolean().optional(),
  showCorrectAnswers: z.boolean().optional(),
  showExplanations: z.boolean().optional(),
  instructions: z.string().optional(),
  sections: z
    .array(
      z.object({
        title: z.string().optional(),
        instructions: z.string().optional(),
        order: z.number().int().min(1),
        timeLimitMinutes: z.number().int().positive().optional(),
        questions: z
          .array(
            z.object({
              questionBankItemId: z.number().int().positive(),
              order: z.number().int().min(1),
              overridePoints: z.number().int().positive().optional(),
            })
          )
          .min(1),
      })
    )
    .min(1),
});

export const assessmentUpdateSchema = assessmentCreateSchema.partial().extend({
  sections: assessmentCreateSchema.shape.sections.optional(),
});

export const attemptAnswerSchema = z.object({
  assessmentQuestionId: z.number().int().positive(),
  answer: z.unknown(),
  timeTakenSeconds: z.number().int().min(0).optional(),
});

// ============ QUESTION BANK ============

const questionOptionSchema = z.object({
  id: z.string(),
  text: z.string(),
  imageUrl: z.string().optional(),
  isCorrect: z.boolean().optional(),
});

const correctAnswerSchema = z.object({
  type: z.enum(["single", "multi", "text", "numeric", "pairs", "order"]),
  value: z.unknown(),
  tolerance: z.number().optional(),
  caseSensitive: z.boolean().optional(),
});

export const questionBankListQuerySchema = z.object({
  subjectId: z.coerce.number().int().positive().optional(),
  moduleId: z.coerce.number().int().positive().optional(),
  difficulty: z.enum(["easy", "medium", "hard", "adaptive"]).optional(),
  type: z.enum(["multiple_choice", "short_answer", "essay"]).optional(),
  source: z
    .enum(["manual", "nsc_past_paper", "exemplar", "textbook", "ai_generated", "imported"])
    .optional(),
  tags: z.union([z.string(), z.array(z.string())]).optional(),
  search: z.string().optional(),
  isActive: z.enum(["true", "false"]).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

export const questionBankCreateSchema = z.object({
  subjectId: z.number().int().positive(),
  moduleId: z.number().int().positive().optional(),
  type: z.enum(["multiple_choice", "short_answer", "essay"]),
  difficulty: z.enum(["easy", "medium", "hard", "adaptive"]).optional(),
  questionText: z.string().min(3),
  questionHtml: z.string().optional(),
  imageUrl: z.string().url().optional(),
  options: z.array(questionOptionSchema).optional(),
  correctAnswer: correctAnswerSchema.optional(),
  explanation: z.string().optional(),
  solutionSteps: z.array(z.string()).optional(),
  points: z.number().int().positive().optional(),
  timeLimitSeconds: z.number().int().positive().optional(),
  source: z
    .enum(["manual", "nsc_past_paper", "exemplar", "textbook", "ai_generated", "imported"])
    .optional(),
  sourceReference: z.string().optional(),
  tags: z.array(z.string()).optional(),
  language: z.string().min(2).max(10).optional(),
});

export const questionBankUpdateSchema = questionBankCreateSchema.partial().extend({
  isActive: z.boolean().optional(),
});

export const questionBankRandomQuerySchema = z.object({
  subjectId: z.coerce.number().int().positive().optional(),
  moduleId: z.coerce.number().int().positive().optional(),
  difficulty: z.enum(["easy", "medium", "hard", "adaptive"]).optional(),
  type: z.enum(["multiple_choice", "short_answer", "essay"]).optional(),
  count: z.coerce.number().int().min(1).max(100).optional(),
  excludeIds: z.union([
    z.coerce.number().int().positive(),
    z.array(z.coerce.number().int().positive()),
  ]).optional(),
});

export const questionBankBulkImportSchema = z.object({
  questions: z.array(questionBankCreateSchema).min(1).max(500),
});

// ============ CURRICULUM ============

export const curriculumCreateSchema = z.object({
  name: z.string().min(2).max(120),
  country: z.string().min(2).max(60),
  description: z.string().optional(),
  isActive: z.boolean().optional(),
});

export const curriculumUpdateSchema = curriculumCreateSchema.partial();

export const gradeCreateSchema = z.object({
  curriculumId: z.number().int().positive(),
  level: z.number().int().min(1).max(12),
  label: z.string().min(2).max(40),
});

export const gradeUpdateSchema = gradeCreateSchema.partial();

export const topicCreateSchema = z.object({
  subjectId: z.number().int().positive(),
  gradeId: z.number().int().positive(),
  parentTopicId: z.number().int().positive().optional(),
  title: z.string().min(2).max(200),
  description: z.string().optional(),
  termNumber: z.number().int().min(1).max(4).optional(),
  capsReference: z.string().max(80).optional(),
  order: z.number().int().min(0).optional(),
  weighting: z.number().int().min(0).max(100).optional(),
});

export const topicUpdateSchema = topicCreateSchema.partial();

export const topicListQuerySchema = z.object({
  subjectId: z.coerce.number().int().positive().optional(),
  gradeId: z.coerce.number().int().positive().optional(),
  parentTopicId: z.coerce.number().int().positive().optional(),
  termNumber: z.coerce.number().int().min(1).max(4).optional(),
});

export const learningOutcomeCreateSchema = z.object({
  topicId: z.number().int().positive(),
  code: z.string().max(40).optional(),
  description: z.string().min(3),
  bloomsLevel: z
    .enum(["remember", "understand", "apply", "analyze", "evaluate", "create"])
    .optional(),
});

export const learningOutcomeUpdateSchema = learningOutcomeCreateSchema.partial();

// ============ NSC PAST PAPERS ============

export const nscPaperListQuerySchema = z.object({
  subjectId: z.coerce.number().int().positive().optional(),
  year: z.coerce.number().int().min(2000).max(2100).optional(),
  session: z.enum(["november", "may_june", "february_march", "supplementary", "exemplar"]).optional(),
  paperNumber: z.coerce.number().int().min(1).max(3).optional(),
  language: z.string().optional(),
  isProcessed: z.enum(["true", "false"]).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

export const nscPaperCreateSchema = z.object({
  subjectId: z.number().int().positive(),
  gradeId: z.number().int().positive().optional(),
  year: z.number().int().min(2000).max(2100),
  session: z.enum(["november", "may_june", "february_march", "supplementary", "exemplar"]),
  paperNumber: z.number().int().min(1).max(3),
  language: z.string().min(2).max(20).optional(),
  totalMarks: z.number().int().positive().optional(),
  durationMinutes: z.number().int().positive().optional(),
  metadata: z.record(z.unknown()).optional(),
});

export const nscPaperUpdateSchema = nscPaperCreateSchema.partial();

export const nscPaperDocumentCreateSchema = z.object({
  docType: z.enum([
    "question_paper",
    "memorandum",
    "marking_guideline",
    "answer_book",
    "data_files",
    "addendum",
    "formula_sheet",
  ]),
  title: z.string().min(3).max(300),
  fileUrl: z.string().url(),
  filePath: z.string().optional(),
  fileSize: z.number().int().positive().optional(),
  mimeType: z.string().max(60).optional(),
  language: z.string().min(2).max(20).optional(),
});

export const nscPaperQuestionCreateSchema = z.object({
  questionNumber: z.string().min(1).max(20),
  questionText: z.string().min(3),
  marks: z.number().int().positive(),
  topicId: z.number().int().positive().optional(),
  sectionLabel: z.string().max(60).optional(),
  imageUrl: z.string().url().optional(),
  memoText: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
});

export const nscPaperQuestionUpdateSchema = nscPaperQuestionCreateSchema.partial();

// ============ MESSAGING ============

export const messageCreateSchema = z.object({
  recipientId: z.string().uuid(),
  subject: z.string().max(200).optional(),
  content: z.string().min(1).max(10000),
});

export const messageListQuerySchema = z.object({
  unreadOnly: z.enum(["true", "false"]).optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

// ============ TIMETABLE ============

export const timetableEntryCreateSchema = z.object({
  subjectId: z.number().int().positive().optional(),
  title: z.string().min(2).max(160),
  dayOfWeek: z.enum(["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]),
  startTime: z.string().regex(/^([01]\d|2[0-3]):([0-5]\d)$/, "Invalid time format (HH:MM)"),
  endTime: z.string().regex(/^([01]\d|2[0-3]):([0-5]\d)$/, "Invalid time format (HH:MM)"),
  location: z.string().max(120).optional(),
  color: z.string().regex(/^#[0-9A-Fa-f]{6}$/, "Invalid hex color").optional(),
  isRecurring: z.boolean().optional(),
});

export const timetableEntryUpdateSchema = timetableEntryCreateSchema.partial();
