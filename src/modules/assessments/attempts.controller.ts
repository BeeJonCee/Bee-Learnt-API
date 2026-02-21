import type { Request, Response } from "express";
import { asyncHandler } from "../../core/middleware/async-handler.js";
import { parseUuid } from "../../shared/utils/parse.js";
import { HttpError } from "../../shared/utils/http-error.js";
import {
  answerAttempt,
  getAttempt,
  getAttemptReview,
  submitAttempt,
} from "./assessments.service.js";

export const getById = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) throw new HttpError("Unauthorized", 401);

  const attemptId = parseUuid(req.params.attemptId as string);
  if (!attemptId) {
    res.status(400).json({ message: "Invalid attempt id" });
    return;
  }

  const attempt = await getAttempt(attemptId);
  if (!attempt) {
    res.status(404).json({ message: "Attempt not found" });
    return;
  }

  const isOwner = attempt.userId === req.user.id;
  const isPrivileged = req.user.role === "ADMIN" || req.user.role === "TUTOR";
  if (!isOwner && !isPrivileged) {
    res.status(403).json({ message: "Forbidden" });
    return;
  }

  res.json({ attempt });
});

export const answer = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) throw new HttpError("Unauthorized", 401);

  const attemptId = parseUuid(req.params.attemptId as string);
  if (!attemptId) {
    res.status(400).json({ message: "Invalid attempt id" });
    return;
  }

  const body = req.body as {
    assessmentQuestionId: number;
    answer: unknown;
    timeTakenSeconds?: number;
  };

  const result = await answerAttempt({
    attemptId,
    userId: req.user.id,
    assessmentQuestionId: body.assessmentQuestionId,
    answer: body.answer,
    timeTakenSeconds: body.timeTakenSeconds,
  });

  res.json(result);
});

export const submit = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) throw new HttpError("Unauthorized", 401);

  const attemptId = parseUuid(req.params.attemptId as string);
  if (!attemptId) {
    res.status(400).json({ message: "Invalid attempt id" });
    return;
  }

  const result = await submitAttempt({ attemptId, userId: req.user.id });
  res.json(result);
});

export const review = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user) throw new HttpError("Unauthorized", 401);

  const attemptId = parseUuid(req.params.attemptId as string);
  if (!attemptId) {
    res.status(400).json({ message: "Invalid attempt id" });
    return;
  }

  const payload = await getAttemptReview({
    attemptId,
    userId: req.user.id,
    role: req.user.role,
  });

  res.json(payload);
});
