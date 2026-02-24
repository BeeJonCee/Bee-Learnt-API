import { HttpError } from "../../shared/utils/http-error.js";

export const STUDENT_VISIBLE_PAPER_STATUSES = [
  "published",
  "closed",
  "marking",
  "released",
] as const;

export function assertDraftPaperStatus(
  status: string,
  message = "Only draft papers can be edited",
): void {
  if (status !== "draft") {
    throw new HttpError(message, 400);
  }
}
