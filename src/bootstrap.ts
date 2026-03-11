import { createLogger } from "./shared/utils/logger.js";

// Import all migration functions
import { migrate as migrateCore } from "./seed/migrate-core.js";
import { migrate as migrateAnnouncementsEvents } from "./seed/migrate-announcements-events.js";
import { migrate as migrateAttendance } from "./seed/migrate-attendance.js";
import { migrate as migrateEducationFeatures } from "./seed/migrate-education-features.js";
import { migrate as migrateAdvancedFeatures } from "./seed/migrate-advanced-features.js";
import { migrate as migrateStudyGoals } from "./seed/migrate-study-goals.js";
import { migrate as migrateAssessments } from "./seed/migrate-assessments.js";
import { migrate as migrateSeedAlignment } from "./seed/migrate-seed-alignment.js";
import { migrate as migrateNscCurriculum } from "./seed/migrate-nsc-curriculum.js";
import { migrate as migrateEducationAssets } from "./seed/migrate-education-assets.js";
import { migrate as migrateSubjectResources } from "./seed/migrate-subject-resources.js";
import { migrate as migrateQuestionBankTypes } from "./seed/migrate-question-bank-types.js";
import { migrate as migrateManualPapers } from "./seed/migrate-manual-papers.js";

const logger = createLogger("bootstrap");

/**
 * Ordered list of migrations that must run on every server start.
 * Each uses `CREATE TABLE IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`
 * so they are idempotent and safe to re-run.
 */
const migrations: { name: string; fn: () => Promise<void> }[] = [
  { name: "core",                  fn: migrateCore },
  { name: "announcements-events",  fn: migrateAnnouncementsEvents },
  { name: "attendance",            fn: migrateAttendance },
  { name: "education-features",    fn: migrateEducationFeatures },
  { name: "advanced-features",     fn: migrateAdvancedFeatures },
  { name: "study-goals",           fn: migrateStudyGoals },
  { name: "assessments",           fn: migrateAssessments },
  { name: "seed-alignment",        fn: migrateSeedAlignment },
  { name: "nsc-curriculum",        fn: migrateNscCurriculum },
  { name: "education-assets",      fn: migrateEducationAssets },
  { name: "subject-resources",     fn: migrateSubjectResources },
  { name: "question-bank-types",   fn: migrateQuestionBankTypes },
  { name: "manual-papers",         fn: migrateManualPapers },
];

/**
 * Run all database migrations in order.
 * Migrations are idempotent — safe to run on every boot.
 */
export async function runMigrations(): Promise<void> {
  logger.info("Running database migrations", { count: migrations.length });
  const start = Date.now();

  for (const { name, fn } of migrations) {
    const t0 = Date.now();
    try {
      await fn();
      logger.debug(`  ✓ migrate:${name}`, { durationMs: Date.now() - t0 });
    } catch (err) {
      logger.error(`  ✗ migrate:${name} failed`, {
        error:      err instanceof Error ? err.message : String(err),
        durationMs: Date.now() - t0,
      });
      throw err; // Abort startup on migration failure
    }
  }

  logger.info("All migrations completed", { durationMs: Date.now() - start });
}

/**
 * Run database seeders (only when SEED_ON_START=true).
 * This is optional and typically used in development.
 */
export async function runSeeders(): Promise<void> {
  logger.info("Running seeders");
  const start = Date.now();

  try {
    // Dynamic import so heavy seed data isn't loaded unless needed
    const { seed } = await import("./seed/seed.js");
    await seed();
    logger.info("Seeders completed", { durationMs: Date.now() - start });
  } catch (err) {
    logger.warn("Seeder failed (non-fatal, continuing startup)", {
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

/**
 * Full bootstrap: migrations + optional seeders.
 * Call this before starting the HTTP server.
 */
export async function bootstrap(): Promise<void> {
  logger.info("Bootstrap started", { env: process.env.NODE_ENV ?? "development" });
  const t0 = Date.now();

  await runMigrations();

  if (process.env.SEED_ON_START === "true") {
    await runSeeders();
  }

  logger.info("Bootstrap complete", { durationMs: Date.now() - t0 });
}
