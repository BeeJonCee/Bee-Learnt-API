import type {
  QuestionBankItem,
  QuestionRenderOptions,
  QuestionOption,
  CorrectAnswer,
  UserAnswer,
  GradingResult,
} from "./questions.types.js";
import { isObjectiveQuestion, supportsPartialCredit } from "./questions.types.js";

/**
 * Question Renderer Service
 * Handles rendering questions for display and validates user answers
 */
export class QuestionRendererService {
  /**
   * Render a question for student attempt (hides correct answers)
   */
  renderForAttempt(
    question: QuestionBankItem,
    options: QuestionRenderOptions = {}
  ): Partial<QuestionBankItem> {
    const {
      shuffleOptions = false,
      showPoints = true,
      showTimeLimit = true,
    } = options;

    // Base rendered question
    const rendered: Partial<QuestionBankItem> = {
      id: question.id,
      type: question.type,
      questionText: question.questionText,
      questionHtml: question.questionHtml,
      imageUrl: question.imageUrl,
      points: showPoints ? question.points : undefined,
      timeLimitSeconds: showTimeLimit ? question.timeLimitSeconds : undefined,
    };

    // Handle options-based questions
    if (question.options && question.options.length > 0) {
      let opts = [...question.options];

      // Remove isCorrect flag for security
      opts = opts.map(({ isCorrect, ...opt }) => opt);

      // Shuffle if requested
      if (shuffleOptions) {
        opts = this.shuffleArray(opts);
      }

      rendered.options = opts;
    }

    // For matching questions, provide separate lists
    if (question.type === "matching" && question.correctAnswer.type === "pairs") {
      const { value, shuffleLeft, shuffleRight } = question.correctAnswer;
      let leftItems = value.map((p) => p.left);
      let rightItems = value.map((p) => p.right);

      if (shuffleLeft !== false) leftItems = this.shuffleArray(leftItems);
      if (shuffleRight !== false) rightItems = this.shuffleArray(rightItems);

      // Store as special format
      rendered.options = [
        { id: "left", text: JSON.stringify(leftItems) },
        { id: "right", text: JSON.stringify(rightItems) },
      ];
    }

    // For ordering questions, provide shuffled items
    if (question.type === "ordering" && question.correctAnswer.type === "order") {
      const items = question.correctAnswer.value;
      rendered.options = this.shuffleArray(items).map((item, idx) => ({
        id: String(idx),
        text: item,
      }));
    }

    return rendered;
  }

  /**
   * Render a question for review (includes correct answers and explanations)
   */
  renderForReview(
    question: QuestionBankItem,
    userAnswer?: UserAnswer,
    gradingResult?: GradingResult
  ): Partial<QuestionBankItem> & { userAnswer?: UserAnswer; gradingResult?: GradingResult } {
    const rendered: any = {
      ...question,
      userAnswer,
      gradingResult,
    };

    // Highlight correct/incorrect options for multiple choice
    if (question.type === "multiple_choice" || question.type === "multi_select") {
      rendered.options = question.options?.map((opt) => ({
        ...opt,
        isCorrect: this.isOptionCorrect(opt.id, question.correctAnswer),
        isUserSelected: this.isOptionSelected(opt.id, userAnswer),
      }));
    }

    return rendered;
  }

  /**
   * Validate that a user answer has the correct structure
   */
  validateAnswerStructure(answer: unknown, questionType: string): { valid: boolean; error?: string } {
    if (!answer || typeof answer !== "object") {
      return { valid: false, error: "Answer must be an object" };
    }

    const ans = answer as any;

    if (!ans.type) {
      return { valid: false, error: "Answer must have a 'type' field" };
    }

    switch (questionType) {
      case "multiple_choice":
      case "true_false":
        if (ans.type !== "single" && ans.type !== "boolean") {
          return { valid: false, error: `Expected type 'single' or 'boolean', got '${ans.type}'` };
        }
        if (typeof ans.value === "undefined") {
          return { valid: false, error: "Answer must have a 'value' field" };
        }
        break;

      case "multi_select":
        if (ans.type !== "multi") {
          return { valid: false, error: `Expected type 'multi', got '${ans.type}'` };
        }
        if (!Array.isArray(ans.value)) {
          return { valid: false, error: "Multi-select answer value must be an array" };
        }
        break;

      case "short_answer":
      case "essay":
        if (ans.type !== "text") {
          return { valid: false, error: `Expected type 'text', got '${ans.type}'` };
        }
        if (typeof ans.value !== "string") {
          return { valid: false, error: "Text answer value must be a string" };
        }
        break;

      case "numeric":
        if (ans.type !== "numeric") {
          return { valid: false, error: `Expected type 'numeric', got '${ans.type}'` };
        }
        if (typeof ans.value !== "number") {
          return { valid: false, error: "Numeric answer value must be a number" };
        }
        break;

      case "matching":
        if (ans.type !== "pairs") {
          return { valid: false, error: `Expected type 'pairs', got '${ans.type}'` };
        }
        if (!Array.isArray(ans.value)) {
          return { valid: false, error: "Matching answer value must be an array of pairs" };
        }
        break;

      case "ordering":
        if (ans.type !== "order") {
          return { valid: false, error: `Expected type 'order', got '${ans.type}'` };
        }
        if (!Array.isArray(ans.value)) {
          return { valid: false, error: "Ordering answer value must be an array" };
        }
        break;

      case "fill_in_blank":
        if (ans.type !== "blanks") {
          return { valid: false, error: `Expected type 'blanks', got '${ans.type}'` };
        }
        if (!Array.isArray(ans.value)) {
          return { valid: false, error: "Fill-in-blank answer value must be an array" };
        }
        break;

      default:
        return { valid: false, error: `Unknown question type: ${questionType}` };
    }

    return { valid: true };
  }

  // ══════════════════════════════════════════════════════════
  // HELPER METHODS
  // ══════════════════════════════════════════════════════════

  private shuffleArray<T>(array: T[]): T[] {
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
  }

  private isOptionCorrect(optionId: string, correctAnswer: CorrectAnswer): boolean {
    if (correctAnswer.type === "single") {
      return correctAnswer.value === optionId;
    }
    if (correctAnswer.type === "multi") {
      return correctAnswer.value.includes(optionId);
    }
    return false;
  }

  private isOptionSelected(optionId: string, userAnswer?: UserAnswer): boolean {
    if (!userAnswer) return false;

    if (userAnswer.type === "single") {
      return userAnswer.value === optionId;
    }
    if (userAnswer.type === "multi") {
      return userAnswer.value.includes(optionId);
    }
    return false;
  }
}

export const questionRenderer = new QuestionRendererService();
