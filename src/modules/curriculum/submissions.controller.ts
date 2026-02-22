import type { Request, Response } from "express";
import { asyncHandler } from "../../core/middleware/async-handler.js";
import { parseNumber } from "../../shared/utils/parse.js";
import {
  getSubmission,
  getSubmissionsByAssignment,
  submitAssignment,
  gradeSubmission,
} from "./submissions.service.js";
import { getAssignmentById } from "./assignments.service.js";

export const getMySubmission = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assignment id" });
    return;
  }
  const userId = req.user?.id;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  const submission = await getSubmission(id, userId);
  res.json(submission ?? null);
});

export const listSubmissions = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assignment id" });
    return;
  }
  const submissions = await getSubmissionsByAssignment(id);
  res.json(submissions);
});

export const submit = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assignment id" });
    return;
  }
  const userId = req.user?.id;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  const assignment = await getAssignmentById(id);
  if (!assignment) {
    res.status(404).json({ message: "Assignment not found" });
    return;
  }

  const { submissionText } = req.body as { submissionText?: unknown };
  const submission = await submitAssignment(
    id,
    userId,
    typeof submissionText === "string" ? submissionText : undefined,
  );
  res.status(201).json(submission);
});

export const grade = asyncHandler(async (req: Request, res: Response) => {
  const id = parseNumber(req.params.id as string);
  if (!id) {
    res.status(400).json({ message: "Invalid assignment id" });
    return;
  }
  const gradedBy = req.user?.id;
  if (!gradedBy) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
  const assignment = await getAssignmentById(id);
  if (!assignment) {
    res.status(404).json({ message: "Assignment not found" });
    return;
  }

  const { rubricId, rubricScores, totalScore, maxScore, feedback } =
    req.body as {
      rubricId?: unknown;
      rubricScores?: unknown;
      totalScore?: unknown;
      maxScore?: unknown;
      feedback?: unknown;
    };

  const result = await gradeSubmission(id, gradedBy, {
    rubricId: typeof rubricId === "number" ? rubricId : undefined,
    rubricScores: Array.isArray(rubricScores) ? rubricScores : undefined,
    totalScore: typeof totalScore === "number" ? totalScore : undefined,
    maxScore: typeof maxScore === "number" ? maxScore : undefined,
    feedback: typeof feedback === "string" ? feedback : undefined,
  });

  if (!result) {
    res.status(404).json({ message: "No submission found to grade" });
    return;
  }
  res.json(result);
});
