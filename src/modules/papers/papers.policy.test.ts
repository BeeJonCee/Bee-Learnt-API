import assert from "node:assert/strict";
import test from "node:test";
import { HttpError } from "../../shared/utils/http-error.js";
import {
  assertDraftPaperStatus,
  STUDENT_VISIBLE_PAPER_STATUSES,
} from "./papers.policy.js";

test("assertDraftPaperStatus allows draft status", () => {
  assert.doesNotThrow(() => assertDraftPaperStatus("draft"));
});

test("assertDraftPaperStatus rejects non-draft status with HttpError", () => {
  assert.throws(
    () => assertDraftPaperStatus("published"),
    (error) =>
      error instanceof HttpError &&
      error.status === 400 &&
      error.message === "Only draft papers can be edited",
  );
});

test("student visible paper statuses exclude draft and archived", () => {
  const visibleStatuses = [...STUDENT_VISIBLE_PAPER_STATUSES] as string[];

  assert.deepEqual(STUDENT_VISIBLE_PAPER_STATUSES, [
    "published",
    "closed",
    "marking",
    "released",
  ]);
  assert.equal(visibleStatuses.includes("draft"), false);
  assert.equal(visibleStatuses.includes("archived"), false);
});
