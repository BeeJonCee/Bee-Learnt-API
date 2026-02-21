/**
 * Question Types & Interfaces for BeeLearnt Assessment Engine
 * Supports 9 question types with validation and grading
 */

// ══════════════════════════════════════════════════════════
// BASE QUESTION TYPES
// ══════════════════════════════════════════════════════════

export type QuestionType =
  | "multiple_choice"
  | "multi_select"
  | "true_false"
  | "short_answer"
  | "essay"
  | "numeric"
  | "matching"
  | "ordering"
  | "fill_in_blank";

export type QuestionDifficulty = "easy" | "medium" | "hard" | "adaptive";

// ══════════════════════════════════════════════════════════
// QUESTION OPTIONS
// ══════════════════════════════════════════════════════════

export interface QuestionOption {
  id: string;                // "A", "B", "C", "D" or UUID
  text: string;
  imageUrl?: string;
  isCorrect?: boolean;       // Optional: some formats embed correctness
}

// ══════════════════════════════════════════════════════════
// CORRECT ANSWER FORMATS (by question type)
// ══════════════════════════════════════════════════════════

export interface MultipleChoiceAnswer {
  type: "single";
  value: string;             // Option ID (e.g., "B")
}

export interface MultiSelectAnswer {
  type: "multi";
  value: string[];           // Array of option IDs (e.g., ["A", "C", "D"])
}

export interface TrueFalseAnswer {
  type: "boolean";
  value: boolean;
}

export interface ShortAnswerConfig {
  type: "text";
  value: string[];           // Array of acceptable answers
  caseSensitive?: boolean;
  exactMatch?: boolean;      // If false, use fuzzy matching
  maxLength?: number;
}

export interface NumericAnswer {
  type: "numeric";
  value: number;
  tolerance?: number;        // ±tolerance (e.g., 0.5 means 9.5-10.5 for answer 10)
  units?: string;            // Optional unit (e.g., "kg", "m/s")
}

export interface MatchPair {
  left: string;
  right: string;
}

export interface MatchingAnswer {
  type: "pairs";
  value: MatchPair[];        // Correct pairs
  shuffleLeft?: boolean;
  shuffleRight?: boolean;
}

export interface OrderingAnswer {
  type: "order";
  value: string[];           // Correct order of item IDs
}

export interface FillInBlankAnswer {
  type: "blanks";
  value: string[];           // Array of correct answers for each blank
  caseSensitive?: boolean;
}

export type CorrectAnswer =
  | MultipleChoiceAnswer
  | MultiSelectAnswer
  | TrueFalseAnswer
  | ShortAnswerConfig
  | NumericAnswer
  | MatchingAnswer
  | OrderingAnswer
  | FillInBlankAnswer;

// ══════════════════════════════════════════════════════════
// USER ANSWER FORMATS (what students submit)
// ══════════════════════════════════════════════════════════

export interface MultipleChoiceUserAnswer {
  type: "single";
  value: string;             // Selected option ID
}

export interface MultiSelectUserAnswer {
  type: "multi";
  value: string[];           // Array of selected option IDs
}

export interface TrueFalseUserAnswer {
  type: "boolean";
  value: boolean;
}

export interface ShortAnswerUserAnswer {
  type: "text";
  value: string;
}

export interface NumericUserAnswer {
  type: "numeric";
  value: number;
  units?: string;
}

export interface MatchingUserAnswer {
  type: "pairs";
  value: MatchPair[];        // Student's pairs
}

export interface OrderingUserAnswer {
  type: "order";
  value: string[];           // Student's order
}

export interface FillInBlankUserAnswer {
  type: "blanks";
  value: string[];           // Student's answers for each blank
}

export type UserAnswer =
  | MultipleChoiceUserAnswer
  | MultiSelectUserAnswer
  | TrueFalseUserAnswer
  | ShortAnswerUserAnswer
  | NumericUserAnswer
  | MatchingUserAnswer
  | OrderingUserAnswer
  | FillInBlankUserAnswer;

// ══════════════════════════════════════════════════════════
// QUESTION BANK ITEM (Database model)
// ══════════════════════════════════════════════════════════

export interface QuestionBankItem {
  id: number;
  subjectId: number;
  topicId?: number;
  learningOutcomeId?: number;
  type: QuestionType;
  difficulty: QuestionDifficulty;
  questionText: string;
  questionHtml?: string;
  imageUrl?: string;
  options?: QuestionOption[];
  correctAnswer: CorrectAnswer;
  explanation?: string;
  solutionSteps?: string[];
  points: number;
  timeLimitSeconds?: number;
  source: "manual" | "nsc_past_paper" | "exemplar" | "textbook" | "ai_generated" | "imported";
  sourceReference?: string;
  nscPaperQuestionId?: number;
  tags: string[];
  language: string;
  isActive: boolean;
  createdBy?: string;
  reviewedBy?: string;
  reviewedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

// ══════════════════════════════════════════════════════════
// QUESTION RENDERING OPTIONS
// ══════════════════════════════════════════════════════════

export interface QuestionRenderOptions {
  includeCorrectAnswer?: boolean;    // false for students, true for review
  includeExplanation?: boolean;
  includeSolutionSteps?: boolean;
  shuffleOptions?: boolean;
  showPoints?: boolean;
  showTimeLimit?: boolean;
}

// ══════════════════════════════════════════════════════════
// GRADING RESULT
// ══════════════════════════════════════════════════════════

export interface GradingResult {
  isCorrect: boolean;
  score: number;                     // Actual score earned
  maxScore: number;                  // Maximum possible score
  percentCorrect: number;            // 0-100
  feedback?: string;                 // Auto-generated feedback
  partialCredit?: {                  // For multi-part questions
    [partId: string]: {
      correct: boolean;
      score: number;
      maxScore: number;
    };
  };
}

// ══════════════════════════════════════════════════════════
// ASSESSMENT ATTEMPT TRACKING
// ══════════════════════════════════════════════════════════

export interface AttemptAnswer {
  attemptId: string;
  assessmentQuestionId: number;
  questionBankItemId: number;
  answer: UserAnswer;
  isCorrect?: boolean;
  score?: number;
  maxScore: number;
  timeTakenSeconds?: number;
  markerComment?: string;
  answeredAt?: Date;
}

// ══════════════════════════════════════════════════════════
// TOPIC MASTERY TRACKING
// ══════════════════════════════════════════════════════════

export interface TopicMastery {
  userId: string;
  topicId: number;
  totalQuestions: number;
  correctAnswers: number;
  masteryPercent: number;            // 0-100
  lastAttemptAt?: Date;
  updatedAt: Date;
}

// ══════════════════════════════════════════════════════════
// VALIDATION HELPERS
// ══════════════════════════════════════════════════════════

export function isObjectiveQuestion(type: QuestionType): boolean {
  return [
    "multiple_choice",
    "multi_select",
    "true_false",
    "numeric",
    "matching",
    "ordering",
    "fill_in_blank",
  ].includes(type);
}

export function isSubjectiveQuestion(type: QuestionType): boolean {
  return ["short_answer", "essay"].includes(type);
}

export function requiresManualGrading(type: QuestionType): boolean {
  return isSubjectiveQuestion(type);
}

export function supportsPartialCredit(type: QuestionType): boolean {
  return ["multi_select", "matching", "fill_in_blank"].includes(type);
}
