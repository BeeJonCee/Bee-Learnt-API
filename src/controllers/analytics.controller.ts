import { asyncHandler } from "../core/middleware/async-handler.js";
import { parseNumber, parseUuid } from "../shared/utils/parse.js";
import {
  getPlatformStats,
  getSubjectAnalytics,
  getTopicMasteryHeatmap,
  getStudentAnalytics,
  getWeakTopics,
  getAssessmentAnalytics,
} from "../services/analytics.service.js";

export const platformStatsHandler = asyncHandler(async (_req, res) => {
  const stats = await getPlatformStats();
  res.json(stats);
});

export const subjectAnalyticsHandler = asyncHandler(async (req, res) => {
  const subjectId = parseNumber(req.params.subjectId as string);
  if (!subjectId) {
    res.status(400).json({ message: "Invalid subject ID" });
    return;
  }

  const analytics = await getSubjectAnalytics(subjectId);
  if (!analytics) {
    res.status(404).json({ message: "Subject not found" });
    return;
  }

  res.json(analytics);
});

export const topicMasteryHeatmapHandler = asyncHandler(async (req, res) => {
  const { subjectId, gradeId } = req.query;

  const heatmap = await getTopicMasteryHeatmap({
    subjectId: subjectId ? Number(subjectId) : undefined,
    gradeId: gradeId ? Number(gradeId) : undefined,
  });

  res.json(heatmap);
});

export const studentAnalyticsHandler = asyncHandler(async (req, res) => {
  const userId = parseUuid(req.params.userId as string);
  if (!userId) {
    res.status(400).json({ message: "Invalid user ID" });
    return;
  }

  // Check permissions: admin/tutor can view any, parent can view linked children
  const requestingUser = req.user!;
  const isPrivileged =
    requestingUser.role === "ADMIN" || requestingUser.role === "TUTOR";
  const isSelf = requestingUser.id === userId;

  // For parents, we'd need to check parent-student link
  // This is simplified - actual implementation should check the link
  if (!isPrivileged && !isSelf && requestingUser.role !== "PARENT") {
    res.status(403).json({ message: "Forbidden" });
    return;
  }

  const analytics = await getStudentAnalytics(userId);
  res.json(analytics);
});

export const weakTopicsHandler = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const { limit } = req.query;

  const weakTopics = await getWeakTopics(
    userId,
    limit ? Number(limit) : undefined
  );

  res.json(weakTopics);
});

export const assessmentAnalyticsHandler = asyncHandler(async (req, res) => {
  const assessmentId = parseNumber(req.params.assessmentId as string);
  if (!assessmentId) {
    res.status(400).json({ message: "Invalid assessment ID" });
    return;
  }

  const analytics = await getAssessmentAnalytics(assessmentId);
  res.json(analytics);
});
