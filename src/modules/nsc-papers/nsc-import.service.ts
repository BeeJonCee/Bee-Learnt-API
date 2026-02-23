import { db } from "../../core/database/index.js";
import { eq } from "drizzle-orm";
import { nscPapers, nscPaperQuestions, questionBankItems, subjects } from "../../core/database/schema/index.js";
import type { CorrectAnswer } from "../questions/questions.types";

/**
 * NSC Paper Import Service
 * Handles importing NSC past paper questions into the question bank
 */
export class NSCImportService {
  /**
   * Import all questions from an NSC paper into the question bank
   * @param nscPaperId - The NSC paper ID
   * @param createdBy - User ID of the admin importing
   * @returns Array of created question bank item IDs
   */
  async importPaperToQuestionBank(
    nscPaperId: number,
    createdBy: string
  ): Promise<{ imported: number[]; skipped: number[]; errors: { questionId: number; error: string }[] }> {
    console.log(`Importing NSC paper ${nscPaperId} to question bank...`);

    const imported: number[] = [];
    const skipped: number[] = [];
    const errors: { questionId: number; error: string }[] = [];

    try {
      // Get paper details
      const paper = await db.query.nscPapers.findFirst({
        where: eq(nscPapers.id, nscPaperId),
        with: {
          subject: true,
          grade: true,
        },
      });

      if (!paper) {
        throw new Error(`NSC paper ${nscPaperId} not found`);
      }

      // Get all questions for this paper
      const questions = await db.query.nscPaperQuestions.findMany({
        where: eq(nscPaperQuestions.nscPaperId, nscPaperId),
      });

      console.log(`Found ${questions.length} questions to import`);

      for (const question of questions) {
        try {
          // Check if already imported
          const existing = await db.query.questionBankItems.findFirst({
            where: eq(questionBankItems.nscPaperQuestionId, question.id),
          });

          if (existing) {
            console.log(`   Question ${question.questionNumber} already in bank (ID: ${existing.id})`);
            skipped.push(question.id);
            continue;
          }

          // Convert NSC question to question bank format
          const questionBankItem = this.convertNSCQuestionToBank(
            question,
            paper.subjectId,
            createdBy
          );

          // Insert into question bank
          const [created] = await db.insert(questionBankItems).values(questionBankItem).returning({ id: questionBankItems.id });

          imported.push(created.id);
          console.log(
            `   Imported Q${question.questionNumber} -> Question Bank ID: ${created.id}`
          );
        } catch (error: any) {
          console.error(`   Error importing Q${question.questionNumber}:`, error.message);
          errors.push({
            questionId: question.id,
            error: error.message,
          });
        }
      }

      // Mark paper as processed
      await db.update(nscPapers).set({ isProcessed: true }).where(eq(nscPapers.id, nscPaperId));

      console.log(
        `Import complete: ${imported.length} imported, ${skipped.length} skipped, ${errors.length} errors`
      );

      return { imported, skipped, errors };
    } catch (error) {
      console.error("Error importing NSC paper:", error);
      throw error;
    }
  }

  /**
   * Convert an NSC paper question to question bank format
   */
  private convertNSCQuestionToBank(
    nscQuestion: any,
    subjectId: number,
    createdBy: string
  ): any {
    // Determine question type based on marks and text analysis
    const questionType = this.inferQuestionType(nscQuestion);

    // Build source reference
    const sourceReference = `NSC ${nscQuestion.questionNumber}`;

    // Parse correct answer from memo text
    const correctAnswer = this.parseMemoToAnswer(nscQuestion.memoText, questionType);

    return {
      subjectId,
      topicId: nscQuestion.topicId,
      type: questionType,
      difficulty: this.inferDifficulty(nscQuestion.marks),
      questionText: nscQuestion.questionText,
      imageUrl: nscQuestion.imageUrl,
      options: null, // NSC questions typically don't have predefined options
      correctAnswer,
      explanation: nscQuestion.memoText,
      solutionSteps: this.extractSolutionSteps(nscQuestion.memoText),
      points: nscQuestion.marks,
      timeLimitSeconds: null,
      source: "nsc_past_paper" as const,
      sourceReference,
      nscPaperQuestionId: nscQuestion.id,
      tags: [nscQuestion.sectionLabel].filter(Boolean),
      language: "en",
      isActive: true,
      createdBy,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  /**
   * Infer question type from NSC question characteristics
   */
  private inferQuestionType(nscQuestion: any): string {
    const text = nscQuestion.questionText.toLowerCase();

    // True/False detection
    if (text.includes("true or false") || text.includes("true/false")) {
      return "true_false";
    }

    // Multiple choice detection (A, B, C, D indicators)
    if (/[a-d]\)/gi.test(text) || text.includes("select the correct")) {
      return "multiple_choice";
    }

    // Numeric answer detection
    if (text.includes("calculate") || text.includes("how many") || text.includes("what is the")) {
      return "numeric";
    }

    // Match detection
    if (text.includes("match") || text.includes("column a") && text.includes("column b")) {
      return "matching";
    }

    // Default to short answer for 1-2 marks, essay for 3+ marks
    return nscQuestion.marks <= 2 ? "short_answer" : "essay";
  }

  /**
   * Infer difficulty based on marks allocated
   */
  private inferDifficulty(marks: number): "easy" | "medium" | "hard" {
    if (marks <= 2) return "easy";
    if (marks <= 5) return "medium";
    return "hard";
  }

  /**
   * Parse memorandum text to extract correct answer
   */
  private parseMemoToAnswer(memoText: string | null, questionType: string): CorrectAnswer {
    if (!memoText) {
      // Default answer structure based on type
      return this.getDefaultAnswer(questionType);
    }

    // Attempt to parse memo based on question type
    switch (questionType) {
      case "multiple_choice":
        const mcMatch = memoText.match(/[A-D]/i);
        return {
          type: "single",
          value: mcMatch ? mcMatch[0].toUpperCase() : "A",
        };

      case "true_false":
        const tfMatch = memoText.toLowerCase().includes("true");
        return {
          type: "boolean",
          value: tfMatch,
        };

      case "numeric":
        const numMatch = memoText.match(/(\d+\.?\d*)/);
        return {
          type: "numeric",
          value: numMatch ? parseFloat(numMatch[1]) : 0,
          tolerance: 0.5,
        };

      case "short_answer":
      case "essay":
        return {
          type: "text",
          value: [memoText.trim()],
          caseSensitive: false,
          exactMatch: false,
        };

      default:
        return this.getDefaultAnswer(questionType);
    }
  }

  /**
   * Get default answer structure for a question type
   */
  private getDefaultAnswer(questionType: string): CorrectAnswer {
    switch (questionType) {
      case "multiple_choice":
        return { type: "single", value: "A" };
      case "multi_select":
        return { type: "multi", value: ["A"] };
      case "true_false":
        return { type: "boolean", value: true };
      case "numeric":
        return { type: "numeric", value: 0, tolerance: 0 };
      case "matching":
        return { type: "pairs", value: [] };
      case "ordering":
        return { type: "order", value: [] };
      case "fill_in_blank":
        return { type: "blanks", value: [] };
      case "short_answer":
      case "essay":
      default:
        return { type: "text", value: [""], caseSensitive: false };
    }
  }

  /**
   * Extract solution steps from memo text
   */
  private extractSolutionSteps(memoText: string | null): string[] {
    if (!memoText) return [];

    // Split by newlines or bullet points
    const steps = memoText
      .split(/\n|•|\-/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && s.length < 200); // Filter out empty or very long lines

    return steps.length > 0 ? steps : [memoText];
  }

  /**
   * Get import status for an NSC paper
   */
  async getImportStatus(nscPaperId: number): Promise<{
    totalQuestions: number;
    importedQuestions: number;
    pendingQuestions: number;
    isProcessed: boolean;
  }> {
    try {
      const paper = await db.query.nscPapers.findFirst({
        where: eq(nscPapers.id, nscPaperId),
      });

      if (!paper) {
        throw new Error(`NSC paper ${nscPaperId} not found`);
      }

      const allQuestions = await db.query.nscPaperQuestions.findMany({
        where: eq(nscPaperQuestions.nscPaperId, nscPaperId),
      });

      const importedQuestions = await db.query.questionBankItems.findMany({
        where: eq(questionBankItems.source, "nsc_past_paper"),
      });

      const importedIds = new Set(
        importedQuestions
          .filter((q) => q.nscPaperQuestionId)
          .map((q) => q.nscPaperQuestionId)
      );

      const totalQuestions = allQuestions.length;
      const imported = allQuestions.filter((q) => importedIds.has(q.id)).length;
      const pending = totalQuestions - imported;

      return {
        totalQuestions,
        importedQuestions: imported,
        pendingQuestions: pending,
        isProcessed: paper.isProcessed,
      };
    } catch (error) {
      console.error("Error getting NSC import status:", error);
      throw error;
    }
  }
}

export const nscImportService = new NSCImportService();
