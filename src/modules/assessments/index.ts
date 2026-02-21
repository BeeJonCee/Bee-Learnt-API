// modules/assessments — barrel export
export * from "./assessments.service.js";
export * from "./assessments.controller.js";
export { getById as getAttemptById, answer, submit, review } from "./attempts.controller.js";
export * from "./grading.service.js";
export * from "./mastery.service.js";
export { assessmentsRoutes } from "./assessments.routes.js";
export { attemptsRoutes } from "./attempts.routes.js";
