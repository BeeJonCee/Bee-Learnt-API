/**
 * Central export point for all database schema tables
 * Imports and re-exports in dependency order
 */

// Enums & Types (Foundation)
export * from "./enums.js";
export * from "./types.js";

// Users (Base entities)
export * from "./users.schema.js";

// System (Independent tables)
export * from "./system.schema.js";

// User Preferences
export * from "./preferences.schema.js";

// Content (Subjects, Modules, Lessons)
export * from "./content.schema.js";

// Curriculum (Depends on content.subjects)
export * from "./curriculum.schema.js";

// Module Unlock System
export * from "./unlock.schema.js";

// Progress Tracking (Depends on curriculum.topics)
export * from "./progress.schema.js";

// Question Bank (Foundation for assessments)
export * from "./questions.schema.js";

// Legacy Quiz System
export * from "./quiz-legacy.schema.js";

// Assessment Engine (Depends on questions)
export * from "./assessments.schema.js";

// Gamification
export * from "./gamification.schema.js";

// Collaboration
export * from "./collaboration.schema.js";

// Tutoring
export * from "./tutoring.schema.js";

// Social & Messaging
export * from "./social.schema.js";

// NSC Past Papers (Depends on curriculum)
export * from "./nsc-papers.schema.js";

// Rubrics
export * from "./rubrics.schema.js";

// Subject Resources (Depends on content + curriculum)
export * from "./subject-resources.schema.js";

// Relations (Drizzle relational query API)
export * from "./relations.js";

// Neon Auth Schema (read-only) + legacy aliases
export * from "../neon-auth-schema.js";

// Backward-compat aliases used by migrated code from the reference backend.
// The reference backend used `neonUsers` as shorthand for `neonAuthUsers`, etc.
import { neonAuthUsers, neonAuthMembers, neonAuthOrganizations } from "../neon-auth-schema.js";
export { neonAuthUsers as neonUsers };
export { neonAuthMembers as neonMembers };
export { neonAuthOrganizations as neonOrganizations };
