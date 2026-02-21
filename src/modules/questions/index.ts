// modules/questions — barrel export
// Types are the canonical source; service re-declares some of the same
// names so we selectively export only functions from the service to
// avoid TS2308 ambiguity errors.
export * from "./questions.types.js";
export {
  listQuestions,
  getQuestionById,
  createQuestion,
  updateQuestion,
  deleteQuestion,
  getRandomQuestions,
  bulkCreateQuestions,
  getQuestionStats,
} from "./question-bank.service.js";
export * from "./question-bank.controller.js";
export * from "./question-renderer.service.js";
export * from "./questions.validators.js";
export { questionBankRoutes } from "./question-bank.routes.js";
