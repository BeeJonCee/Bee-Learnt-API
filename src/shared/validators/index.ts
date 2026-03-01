import { z } from "zod";

// Re-export everything from sub-validator files
export * from "./questions.validators.js";
export * from "./subject-resources.validators.js";
export * from "./notifications.validators.js";

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
      "long_answer",
      "numeric",
      "matching",
      "ordering",
      "fill_in_blank",
      "code_practical",
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
        "long_answer",
        "numeric",
        "matching",
        "ordering",
        "fill_in_blank",
        "code_practical",
      ]),
      questionText: z.string().min(1),
      options: z.array(z.any()).optional(),
      correctAnswer: z.any().optional(),
      difficulty: z.enum(["easy", "medium", "hard", "adaptive"]).default("medium"),
      points: z.number().int().positive().default(1),
      answerFormat: z.enum([
        "one_word",
        "number",
        "short_sentence",
        "sql_snippet",
        "code_line",
        "paragraph",
        "code_block",
      ]).optional(),
      rubricCriteria: z.array(
        z.object({
          criterion: z.string().min(1),
          marks: z.number().positive(),
          description: z.string().optional(),
        }),
      ).optional(),
      practicalConfig: z.object({
        mode: z.enum(["editor", "file_upload", "both"]).optional(),
        language: z.string().optional(),
        allowFileUpload: z.boolean().optional(),
        acceptedFileExtensions: z.array(z.string()).optional(),
        starterCode: z.string().optional(),
      }).optional(),
      modelAnswer: z.string().optional(),
      memo: z.string().optional(),
      explanation: z.string().optional(),
      tags: z.array(z.string()).default([]),
      topicId: z.number().int().positive().optional(),
      learningOutcomeId: z.number().int().positive().optional(),
    })
  ).min(1),
});

// ─── Auth ─────────────────────────────────────────────────────────────────────

export const loginSchema = z.object({
  // Accept email address or E.164 phone number (+27821234567)
  email: z.string().min(1),
  password: z.string().min(6),
});

export const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  name: z.string().min(1).max(120),
  phone: z
    .string()
    .regex(/^\+\d{7,15}$/, "Phone must be E.164 format, e.g. +27821234567")
    .optional(),
  role: z.enum(["STUDENT", "PARENT"]),
});

export const authVerificationSendSchema = z.object({
  channel: z.enum(["email", "sms"]),
  target: z.string().min(1),
  purpose: z.enum(["email_verification", "phone_verification"]).optional(),
});

export const authVerificationVerifySchema = z.object({
  channel: z.enum(["email", "sms"]),
  target: z.string().min(1),
  code: z.string().regex(/^\d{6}$/, "Code must be 6 digits"),
});

export const authPreferencesUpdateSchema = z
  .object({
    loginEmailAlertEnabled: z.boolean().optional(),
    loginSmsAlertEnabled: z.boolean().optional(),
  })
  .refine(
    (value) =>
      value.loginEmailAlertEnabled !== undefined ||
      value.loginSmsAlertEnabled !== undefined,
    {
      message: "At least one preference field must be provided",
    },
  );

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
  session: z.enum(["november", "may_june", "february_march", "supplementary", "exemplar"]).optional(),
  paperNumber: z.coerce.number().int().positive().optional(),
  language: z.string().optional(),
  isProcessed: z.coerce.boolean().optional(),
  limit: z.coerce.number().int().positive().max(200).optional(),
  offset: z.coerce.number().int().nonnegative().optional(),
});

const coerceRequiredPositiveInt = () =>
  z.preprocess((value) => {
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (!trimmed) return value;
      const parsed = Number(trimmed);
      return Number.isFinite(parsed) ? parsed : value;
    }
    return value;
  }, z.number().int().positive());

const coerceOptionalPositiveInt = () =>
  z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (!trimmed) return undefined;
      const parsed = Number(trimmed);
      return Number.isFinite(parsed) ? parsed : value;
    }
    return value;
  }, z.number().int().positive().optional());

const coerceOptionalBoolean = () =>
  z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (["true", "1", "yes", "on"].includes(normalized)) return true;
      if (["false", "0", "no", "off"].includes(normalized)) return false;
    }
    return value;
  }, z.boolean().optional());

export const nscPaperCreateSchema = z.object({
  subjectId: coerceRequiredPositiveInt(),
  gradeId: coerceOptionalPositiveInt(),
  year: z.preprocess((value) => {
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (!trimmed) return value;
      const parsed = Number(trimmed);
      return Number.isFinite(parsed) ? parsed : value;
    }
    return value;
  }, z.number().int().min(2000).max(2100)),
  session: z.enum(["november", "may_june", "february_march", "supplementary", "exemplar"]),
  paperNumber: coerceRequiredPositiveInt().default(1),
  language: z.string().optional(),
  totalMarks: coerceOptionalPositiveInt(),
  durationMinutes: coerceOptionalPositiveInt(),
  title: z.string().max(200).optional(),
  instructions: z.string().optional(),
  strictMode: coerceOptionalBoolean(),
  isProcessed: coerceOptionalBoolean(),
  sections: z
    .array(
      z.object({
        label: z.string().min(1).max(10),
        title: z.string().max(100).optional(),
        instructions: z.string().optional(),
        totalMarks: z.preprocess((value) => {
          if (value === undefined || value === null || value === "") return undefined;
          if (typeof value === "string") {
            const trimmed = value.trim();
            if (!trimmed) return undefined;
            const parsed = Number(trimmed);
            return Number.isFinite(parsed) ? parsed : value;
          }
          return value;
        }, z.number().int().nonnegative().optional()),
      }),
    )
    .optional(),
  // Allow freeform metadata JSONB (used by the builder to store sections, strictMode, etc.)
  metadata: z.record(z.unknown()).optional(),
});

export const nscPaperUpdateSchema = nscPaperCreateSchema.partial();

export const nscPaperDocumentCreateSchema = z.object({
  title: z.string().min(1).max(200),
  fileUrl: z.string().url(),
  docType: z.enum([
    "question_paper",
    "memorandum",
    "marking_guideline",
    "answer_book",
    "data_files",
    "addendum",
    "formula_sheet",
  ]),
  language: z.string().optional(),
  mimeType: z.string().optional(),
  fileSize: z.number().int().positive().optional(),
});

export const nscPaperQuestionCreateSchema = z.object({
  questionText: z.string().min(1),
  options: z.array(z.any()).optional(),
  correctAnswer: z.any().optional(),
  topicId: z.number().int().positive().optional(),
  difficulty: z.enum(["easy", "medium", "hard"]).optional(),
  marks: z.number().int().positive().default(1),
  order: z.number().int().nonnegative().default(0),
  sectionLabel: z.string().optional(),
  questionNumber: z.string().optional(),
  memoText: z.string().optional(),
  type: z
    .enum(["mcq", "multi_select", "short_answer", "long_answer", "code_practical"])
    .optional(),
  answerFormat: z
    .enum(["one_word", "number", "short_sentence", "sql_snippet", "code_line"])
    .optional(),
  rubricCriteria: z
    .array(z.object({ criterion: z.string().min(1), marks: z.number().positive() }))
    .optional(),
  modelAnswer: z.string().optional(),
  language: z.string().optional(),
  starterCode: z.string().optional(),
  practicalMode: z.enum(["editor", "upload", "both"]).optional(),
  tags: z.array(z.string()).optional(),
  imageUrl: z.string().url().optional(),
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

export const lessonNoteUpdateSchema = z.object({
  content: z.string().min(1),
});

export const lessonNoteQuerySchema = z.object({
  lessonId: z.coerce.number().int().positive().optional(),
  moduleId: z.coerce.number().int().positive().optional(),
});

// ─── Timetable ────────────────────────────────────────────────────────────────

const dayOfWeek = z.enum([
  "monday",
  "tuesday",
  "wednesday",
  "thursday",
  "friday",
  "saturday",
  "sunday",
]);

const timetableDayInputSchema = z.preprocess((value) => {
  if (typeof value === "string") {
    return value.trim().toLowerCase();
  }
  return value;
}, dayOfWeek);

const timetableEntryPayloadSchema = z.object({
  title: z.string().min(1).max(120),
  dayOfWeek: timetableDayInputSchema.optional(),
  // Backward compatibility for older clients that still send `day`.
  day: timetableDayInputSchema.optional(),
  startTime: z.string().regex(/^\d{2}:\d{2}$/, "Must be HH:MM"),
  endTime: z.string().regex(/^\d{2}:\d{2}$/, "Must be HH:MM"),
  subjectId: z.coerce.number().int().positive().optional(),
  location: z.string().max(120).optional(),
  isRecurring: z.boolean().default(true),
  color: z.string().optional(),
});

export const timetableEntryCreateSchema = timetableEntryPayloadSchema
  .superRefine((data, ctx) => {
    if (!data.dayOfWeek && !data.day) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["dayOfWeek"],
        message: "Required",
      });
    }
  })
  .transform((data) => {
    const { day, dayOfWeek, ...rest } = data;
    return { ...rest, dayOfWeek: dayOfWeek ?? day };
  });

export const timetableEntryUpdateSchema = timetableEntryPayloadSchema
  .partial()
  .transform((data) => {
    const { day, dayOfWeek, ...rest } = data;
    if (dayOfWeek !== undefined || day !== undefined) {
      return { ...rest, dayOfWeek: dayOfWeek ?? day };
    }
    return rest;
  });

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


// ─── Events ───────────────────────────────────────────────────────────────────


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

const quizSubmitAnswerSchema = z
  .union([
    z.object({
      questionId: z.number().int().positive(),
      answer: z.unknown().refine((value) => value !== undefined, {
        message: "answer is required",
      }),
    }),
    z.object({
      questionId: z.number().int().positive(),
      selectedOption: z.union([z.string(), z.number(), z.boolean()]),
    }),
    // Backward compatibility for typo seen in older clients.
    z.object({
      questionId: z.number().int().positive(),
      selesctedOption: z.union([z.string(), z.number(), z.boolean()]),
    }),
  ])
  .transform((entry) => ({
    questionId: entry.questionId,
    answer:
      "answer" in entry
        ? entry.answer
        : "selectedOption" in entry
          ? entry.selectedOption
          : entry.selesctedOption,
  }));

export const quizSubmitSchema = z.object({
  quizId: z.coerce.number().int().positive(),
  answers: z.array(quizSubmitAnswerSchema).min(1),
});

export const quizQuerySchema = z.object({
  subjectId: z.coerce.number().int().positive().optional(),
  topicId: z.coerce.number().int().positive().optional(),
  moduleId: z.coerce.number().int().positive().optional(),
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
  questionId: z.number().int().positive(),
  answer: z.union([z.string(), z.number(), z.boolean()]),
});
