// ─── Routes ────────────────────────────────────────────────────────
export { assignmentsRoutes } from "./assignments.routes.js";
export { rubricsRoutes } from "./rubrics.routes.js";
export { checklistsRoutes } from "./checklists.routes.js";
export { curriculumRoutes } from "./curriculum.routes.js";
export { learningPathRoutes } from "./learning-path.routes.js";
export { lessonsRoutes } from "./lessons.routes.js";
export { default as moduleAssignmentsRoutes } from "./module-assignments.routes.js";
export { default as moduleUnlockRoutes } from "./module-unlock.routes.js";
export { modulesRoutes } from "./modules.routes.js";
export { resourcesRoutes } from "./resources.routes.js";
export { subjectResourcesRoutes } from "./subject-resources.routes.js";
export { subjectsRoutes } from "./subjects.routes.js";
export { userModulesRoutes } from "./user-modules.routes.js";

// ─── Services ──────────────────────────────────────────────────────
export * from "./assignments.service.js";
export * from "./rubrics.service.js";
export * from "./submissions.service.js";
export * from "./checklists.service.js";
export * from "./curriculum.service.js";
export * from "./education.service.js";
export * from "./lessons.service.js";
export * from "./modules.service.js";
export * from "./resources.service.js";
export * from "./subject-resources.service.js";
export * from "./subjects.service.js";
