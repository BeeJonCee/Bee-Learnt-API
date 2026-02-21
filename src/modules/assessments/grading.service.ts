import type {
  QuestionBankItem,
  UserAnswer,
  GradingResult,
  CorrectAnswer,
  MatchPair,
} from "../questions/questions.types";
import { isObjectiveQuestion, supportsPartialCredit } from "../questions/questions.types";

/**
 * Grading Service
 * Handles auto-grading for objective question types
 * Supports partial credit for multi-select, matching, and fill-in-blank questions
 */
export class GradingService {
  /**
   * Grade a user's answer against a question
   */
  gradeAnswer(question: QuestionBankItem, userAnswer: UserAnswer): GradingResult {
    // Subjective questions (essay, short answer with fuzzy matching) need manual grading
    if (question.type === "essay") {
      return this.requiresManualGrading(question.points);
    }

    // Route to appropriate grading method
    switch (question.type) {
      case "multiple_choice":
      case "true_false":
        return this.gradeSingleChoice(question, userAnswer);

      case "multi_select":
        return this.gradeMultiSelect(question, userAnswer);

      case "short_answer":
        return this.gradeShortAnswer(question, userAnswer);

      case "numeric":
        return this.gradeNumeric(question, userAnswer);

      case "matching":
        return this.gradeMatching(question, userAnswer);

      case "ordering":
        return this.gradeOrdering(question, userAnswer);

      case "fill_in_blank":
        return this.gradeFillInBlank(question, userAnswer);

      default:
        throw new Error(`Unsupported question type: ${question.type}`);
    }
  }

  // ══════════════════════════════════════════════════════════
  // GRADING METHODS BY QUESTION TYPE
  // ══════════════════════════════════════════════════════════

  /**
   * Grade single-choice questions (multiple choice, true/false)
   */
  private gradeSingleChoice(question: QuestionBankItem, userAnswer: UserAnswer): GradingResult {
    const correctAns = question.correctAnswer as any;
    const userAns = userAnswer as any;

    const isCorrect = correctAns.value === userAns.value;

    return {
      isCorrect,
      score: isCorrect ? question.points : 0,
      maxScore: question.points,
      percentCorrect: isCorrect ? 100 : 0,
      feedback: isCorrect ? "Correct!" : `Incorrect. The correct answer is: ${correctAns.value}`,
    };
  }

  /**
   * Grade multi-select questions (with partial credit)
   */
  private gradeMultiSelect(question: QuestionBankItem, userAnswer: UserAnswer): GradingResult {
    const correctAns = question.correctAnswer as any;
    const userAns = userAnswer as any;

    if (!Array.isArray(correctAns.value) || !Array.isArray(userAns.value)) {
      return this.invalidAnswerResult(question.points);
    }

    const correctSet = new Set(correctAns.value);
    const userSet = new Set(userAns.value);

    // Calculate partial credit
    const correctSelections = [...userSet].filter((id) => correctSet.has(id)).length;
    const incorrectSelections = [...userSet].filter((id) => !correctSet.has(id)).length;
    const missedSelections = [...correctSet].filter((id) => !userSet.has(id)).length;

    // Partial credit formula: (correct - incorrect) / total correct, minimum 0
    const totalCorrect = correctSet.size;
    const partialScore = Math.max(0, (correctSelections - incorrectSelections) / totalCorrect);
    const score = Math.round(partialScore * question.points * 100) / 100;

    const isCorrect = correctSelections === totalCorrect && incorrectSelections === 0;
    const percentCorrect = Math.round(partialScore * 100);

    return {
      isCorrect,
      score,
      maxScore: question.points,
      percentCorrect,
      feedback: isCorrect
        ? "All correct!"
        : `Partial credit: ${correctSelections} correct, ${incorrectSelections} incorrect, ${missedSelections} missed.`,
    };
  }

  /**
   * Grade short answer questions (exact match or configured alternatives)
   */
  private gradeShortAnswer(question: QuestionBankItem, userAnswer: UserAnswer): GradingResult {
    const correctAns = question.correctAnswer as any;
    const userAns = userAnswer as any;

    if (typeof userAns.value !== "string") {
      return this.invalidAnswerResult(question.points);
    }

    const userText = userAns.value.trim();
    const acceptableAnswers = Array.isArray(correctAns.value)
      ? correctAns.value
      : [correctAns.value];

    const caseSensitive = correctAns.caseSensitive !== false;
    const exactMatch = correctAns.exactMatch !== false;

    let isCorrect = false;

    if (exactMatch) {
      // Exact match mode
      isCorrect = acceptableAnswers.some((ans: string) => {
        const compare = caseSensitive ? ans : ans.toLowerCase();
        const userCompare = caseSensitive ? userText : userText.toLowerCase();
        return compare === userCompare;
      });
    } else {
      // Fuzzy match mode (contains)
      isCorrect = acceptableAnswers.some((ans: string) => {
        const compare = caseSensitive ? ans : ans.toLowerCase();
        const userCompare = caseSensitive ? userText : userText.toLowerCase();
        return userCompare.includes(compare) || compare.includes(userCompare);
      });
    }

    return {
      isCorrect,
      score: isCorrect ? question.points : 0,
      maxScore: question.points,
      percentCorrect: isCorrect ? 100 : 0,
      feedback: isCorrect
        ? "Correct!"
        : `Your answer does not match the expected response. Acceptable answers: ${acceptableAnswers.join(", ")}`,
    };
  }

  /**
   * Grade numeric questions (with tolerance)
   */
  private gradeNumeric(question: QuestionBankItem, userAnswer: UserAnswer): GradingResult {
    const correctAns = question.correctAnswer as any;
    const userAns = userAnswer as any;

    if (typeof userAns.value !== "number") {
      return this.invalidAnswerResult(question.points);
    }

    const correctValue = correctAns.value;
    const userValue = userAns.value;
    const tolerance = correctAns.tolerance || 0;

    const lowerBound = correctValue - tolerance;
    const upperBound = correctValue + tolerance;

    const isCorrect = userValue >= lowerBound && userValue <= upperBound;

    return {
      isCorrect,
      score: isCorrect ? question.points : 0,
      maxScore: question.points,
      percentCorrect: isCorrect ? 100 : 0,
      feedback: isCorrect
        ? `Correct! (Accepted range: ${lowerBound} - ${upperBound})`
        : `Incorrect. The correct answer is ${correctValue} ±${tolerance}.`,
    };
  }

  /**
   * Grade matching questions (with partial credit)
   */
  private gradeMatching(question: QuestionBankItem, userAnswer: UserAnswer): GradingResult {
    const correctAns = question.correctAnswer as any;
    const userAns = userAnswer as any;

    if (!Array.isArray(correctAns.value) || !Array.isArray(userAns.value)) {
      return this.invalidAnswerResult(question.points);
    }

    const correctPairs = correctAns.value as MatchPair[];
    const userPairs = userAns.value as MatchPair[];

    // Count correct matches
    let correctMatches = 0;
    for (const userPair of userPairs) {
      const isCorrect = correctPairs.some(
        (cp) => cp.left === userPair.left && cp.right === userPair.right
      );
      if (isCorrect) correctMatches++;
    }

    const totalPairs = correctPairs.length;
    const partialScore = correctMatches / totalPairs;
    const score = Math.round(partialScore * question.points * 100) / 100;

    const isCorrect = correctMatches === totalPairs;
    const percentCorrect = Math.round(partialScore * 100);

    return {
      isCorrect,
      score,
      maxScore: question.points,
      percentCorrect,
      feedback: isCorrect
        ? "All pairs matched correctly!"
        : `Partial credit: ${correctMatches} of ${totalPairs} pairs correct.`,
    };
  }

  /**
   * Grade ordering questions (all or nothing, or partial based on position)
   */
  private gradeOrdering(question: QuestionBankItem, userAnswer: UserAnswer): GradingResult {
    const correctAns = question.correctAnswer as any;
    const userAns = userAnswer as any;

    if (!Array.isArray(correctAns.value) || !Array.isArray(userAns.value)) {
      return this.invalidAnswerResult(question.points);
    }

    const correctOrder = correctAns.value as string[];
    const userOrder = userAns.value as string[];

    // Check if orders match exactly
    const isCorrect =
      correctOrder.length === userOrder.length &&
      correctOrder.every((item, idx) => item === userOrder[idx]);

    // Optional: Partial credit based on correct positions
    const correctPositions = correctOrder.filter((item, idx) => item === userOrder[idx]).length;
    const partialScore = correctPositions / correctOrder.length;
    const score = isCorrect ? question.points : Math.round(partialScore * question.points * 100) / 100;

    return {
      isCorrect,
      score,
      maxScore: question.points,
      percentCorrect: Math.round(partialScore * 100),
      feedback: isCorrect
        ? "Perfect order!"
        : `${correctPositions} of ${correctOrder.length} items in correct position.`,
    };
  }

  /**
   * Grade fill-in-blank questions (with partial credit)
   */
  private gradeFillInBlank(question: QuestionBankItem, userAnswer: UserAnswer): GradingResult {
    const correctAns = question.correctAnswer as any;
    const userAns = userAnswer as any;

    if (!Array.isArray(correctAns.value) || !Array.isArray(userAns.value)) {
      return this.invalidAnswerResult(question.points);
    }

    const correctBlanks = correctAns.value as string[];
    const userBlanks = userAns.value as string[];

    if (correctBlanks.length !== userBlanks.length) {
      return this.invalidAnswerResult(question.points);
    }

    const caseSensitive = correctAns.caseSensitive !== false;

    // Count correct blanks
    let correctCount = 0;
    for (let i = 0; i < correctBlanks.length; i++) {
      const correct = caseSensitive ? correctBlanks[i] : correctBlanks[i].toLowerCase();
      const user = caseSensitive ? userBlanks[i].trim() : userBlanks[i].trim().toLowerCase();
      if (correct === user) correctCount++;
    }

    const totalBlanks = correctBlanks.length;
    const partialScore = correctCount / totalBlanks;
    const score = Math.round(partialScore * question.points * 100) / 100;

    const isCorrect = correctCount === totalBlanks;
    const percentCorrect = Math.round(partialScore * 100);

    return {
      isCorrect,
      score,
      maxScore: question.points,
      percentCorrect,
      feedback: isCorrect
        ? "All blanks correct!"
        : `Partial credit: ${correctCount} of ${totalBlanks} blanks correct.`,
    };
  }

  // ══════════════════════════════════════════════════════════
  // HELPER METHODS
  // ══════════════════════════════════════════════════════════

  private requiresManualGrading(maxScore: number): GradingResult {
    return {
      isCorrect: false,
      score: 0,
      maxScore,
      percentCorrect: 0,
      feedback: "This question requires manual grading by an instructor.",
    };
  }

  private invalidAnswerResult(maxScore: number): GradingResult {
    return {
      isCorrect: false,
      score: 0,
      maxScore,
      percentCorrect: 0,
      feedback: "Invalid answer format.",
    };
  }
}

export const gradingService = new GradingService();
