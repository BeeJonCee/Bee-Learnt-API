import { z } from "zod";

/**
 * Zod Validators for Question Types
 * Used for validating user answers and question bank items
 */

// ══════════════════════════════════════════════════════════
// QUESTION OPTION SCHEMA
// ══════════════════════════════════════════════════════════

export const questionOptionSchema = z.object({
  id: z.string(),
  text: z.string().min(1),
  imageUrl: z.string().url().optional(),
  isCorrect: z.boolean().optional(),
});

// ══════════════════════════════════════════════════════════
// CORRECT ANSWER SCHEMAS (by type)
// ══════════════════════════════════════════════════════════

export const multipleChoiceAnswerSchema = z.object({
  type: z.literal("single"),
  value: z.string(),
});

export const multiSelectAnswerSchema = z.object({
  type: z.literal("multi"),
  value: z.array(z.string()).min(1),
});

export const trueFalseAnswerSchema = z.object({
  type: z.literal("boolean"),
  value: z.boolean(),
});

export const shortAnswerConfigSchema = z.object({
  type: z.literal("text"),
  value: z.array(z.string()).min(1),
  caseSensitive: z.boolean().optional(),
  exactMatch: z.boolean().optional(),
  maxLength: z.number().positive().optional(),
});

export const numericAnswerSchema = z.object({
  type: z.literal("numeric"),
  value: z.number(),
  tolerance: z.number().nonnegative().optional(),
  units: z.string().optional(),
});

export const matchPairSchema = z.object({
  left: z.string().min(1),
  right: z.string().min(1),
});

export const matchingAnswerSchema = z.object({
  type: z.literal("pairs"),
  value: z.array(matchPairSchema).min(1),
  shuffleLeft: z.boolean().optional(),
  shuffleRight: z.boolean().optional(),
});

export const orderingAnswerSchema = z.object({
  type: z.literal("order"),
  value: z.array(z.string()).min(2),
});

export const fillInBlankAnswerSchema = z.object({
  type: z.literal("blanks"),
  value: z.array(z.string()).min(1),
  caseSensitive: z.boolean().optional(),
});

export const correctAnswerSchema = z.union([
  multipleChoiceAnswerSchema,
  multiSelectAnswerSchema,
  trueFalseAnswerSchema,
  shortAnswerConfigSchema,
  numericAnswerSchema,
  matchingAnswerSchema,
  orderingAnswerSchema,
  fillInBlankAnswerSchema,
]);

// ══════════════════════════════════════════════════════════
// USER ANSWER SCHEMAS (by type)
// ══════════════════════════════════════════════════════════

export const multipleChoiceUserAnswerSchema = z.object({
  type: z.literal("single"),
  value: z.string(),
});

export const multiSelectUserAnswerSchema = z.object({
  type: z.literal("multi"),
  value: z.array(z.string()),
});

export const trueFalseUserAnswerSchema = z.object({
  type: z.literal("boolean"),
  value: z.boolean(),
});

export const shortAnswerUserAnswerSchema = z.object({
  type: z.literal("text"),
  value: z.string(),
});

export const numericUserAnswerSchema = z.object({
  type: z.literal("numeric"),
  value: z.number(),
  units: z.string().optional(),
});

export const matchingUserAnswerSchema = z.object({
  type: z.literal("pairs"),
  value: z.array(matchPairSchema),
});

export const orderingUserAnswerSchema = z.object({
  type: z.literal("order"),
  value: z.array(z.string()),
});

export const fillInBlankUserAnswerSchema = z.object({
  type: z.literal("blanks"),
  value: z.array(z.string()),
});

export const userAnswerSchema = z.union([
  multipleChoiceUserAnswerSchema,
  multiSelectUserAnswerSchema,
  trueFalseUserAnswerSchema,
  shortAnswerUserAnswerSchema,
  numericUserAnswerSchema,
  matchingUserAnswerSchema,
  orderingUserAnswerSchema,
  fillInBlankUserAnswerSchema,
]);

// ══════════════════════════════════════════════════════════
// QUESTION BANK ITEM SCHEMA
// ══════════════════════════════════════════════════════════

export const questionTypeSchema = z.enum([
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

export const questionDifficultySchema = z.enum(["easy", "medium", "hard", "adaptive"]);

export const questionSourceSchema = z.enum([
  "manual",
  "nsc_past_paper",
  "exemplar",
  "textbook",
  "ai_generated",
  "imported",
]);

export const createQuestionBankItemSchema = z.object({
  subjectId: z.number().int().positive(),
  topicId: z.number().int().positive().optional(),
  learningOutcomeId: z.number().int().positive().optional(),
  type: questionTypeSchema,
  difficulty: questionDifficultySchema.default("medium"),
  questionText: z.string().min(10).max(5000),
  questionHtml: z.string().optional(),
  imageUrl: z.string().url().optional(),
  options: z.array(questionOptionSchema).optional(),
  correctAnswer: correctAnswerSchema,
  explanation: z.string().max(2000).optional(),
  solutionSteps: z.array(z.string()).optional(),
  points: z.number().int().positive().default(1),
  timeLimitSeconds: z.number().int().positive().optional(),
  source: questionSourceSchema.default("manual"),
  sourceReference: z.string().max(200).optional(),
  nscPaperQuestionId: z.number().int().positive().optional(),
  tags: z.array(z.string()).default([]),
  language: z.string().length(2).default("en"),
});

export const updateQuestionBankItemSchema = createQuestionBankItemSchema.partial();

// ══════════════════════════════════════════════════════════
// ASSESSMENT SCHEMAS
// ══════════════════════════════════════════════════════════

export const assessmentTypeSchema = z.enum([
  "quiz",
  "test",
  "exam",
  "practice",
  "nsc_simulation",
  "diagnostic",
]);

export const assessmentStatusSchema = z.enum(["draft", "published", "archived"]);

export const createAssessmentSchema = z.object({
  title: z.string().min(3).max(200),
  description: z.string().max(1000).optional(),
  type: assessmentTypeSchema,
  status: assessmentStatusSchema.default("draft"),
  subjectId: z.number().int().positive(),
  gradeId: z.number().int().positive().optional(),
  topicId: z.number().int().positive().optional(),
  moduleId: z.number().int().positive().optional(),
  nscPaperId: z.number().int().positive().optional(),
  timeLimitMinutes: z.number().int().positive().optional(),
  totalMarks: z.number().int().positive().optional(),
  passMark: z.number().int().positive().optional(),
  maxAttempts: z.number().int().positive().optional(),
  shuffleQuestions: z.boolean().default(false),
  shuffleOptions: z.boolean().default(false),
  showResultsImmediately: z.boolean().default(true),
  showCorrectAnswers: z.boolean().default(true),
  showExplanations: z.boolean().default(true),
  availableFrom: z.string().datetime().optional(),
  availableUntil: z.string().datetime().optional(),
  instructions: z.string().max(2000).optional(),
});

export const updateAssessmentSchema = createAssessmentSchema.partial();

// ══════════════════════════════════════════════════════════
// ATTEMPT ANSWER SCHEMA
// ══════════════════════════════════════════════════════════

export const submitAnswerSchema = z.object({
  assessmentQuestionId: z.number().int().positive(),
  answer: userAnswerSchema,
  timeTakenSeconds: z.number().int().nonnegative().optional(),
});

// ══════════════════════════════════════════════════════════
// QUERY FILTER SCHEMAS
// ══════════════════════════════════════════════════════════

export const questionBankFiltersSchema = z.object({
  subjectId: z.number().int().positive().optional(),
  topicId: z.number().int().positive().optional(),
  difficulty: questionDifficultySchema.optional(),
  type: questionTypeSchema.optional(),
  source: questionSourceSchema.optional(),
  tags: z.string().optional(), // Comma-separated
  search: z.string().optional(),
  page: z.number().int().positive().default(1),
  limit: z.number().int().positive().max(100).default(20),
});

export const assessmentFiltersSchema = z.object({
  type: assessmentTypeSchema.optional(),
  subjectId: z.number().int().positive().optional(),
  gradeId: z.number().int().positive().optional(),
  status: assessmentStatusSchema.optional(),
  page: z.number().int().positive().default(1),
  limit: z.number().int().positive().max(100).default(20),
});

// ══════════════════════════════════════════════════════════
// TYPE EXPORTS (inferred from Zod schemas)
// ══════════════════════════════════════════════════════════

export type CreateQuestionBankItemInput = z.infer<typeof createQuestionBankItemSchema>;
export type UpdateQuestionBankItemInput = z.infer<typeof updateQuestionBankItemSchema>;
export type CreateAssessmentInput = z.infer<typeof createAssessmentSchema>;
export type UpdateAssessmentInput = z.infer<typeof updateAssessmentSchema>;
export type SubmitAnswerInput = z.infer<typeof submitAnswerSchema>;
export type QuestionBankFilters = z.infer<typeof questionBankFiltersSchema>;
export type AssessmentFilters = z.infer<typeof assessmentFiltersSchema>;
