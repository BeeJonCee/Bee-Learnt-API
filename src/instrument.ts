import { logWarn } from "./shared/utils/logger.js";

const tracesSampleRate = Number(process.env.SENTRY_TRACES_SAMPLE_RATE ?? "0");

if (process.env.SENTRY_DSN) {
  try {
    const Sentry = await import("@sentry/node");

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    Sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: process.env.SENTRY_ENVIRONMENT ?? process.env.NODE_ENV ?? "development",
      tracesSampleRate: Number.isFinite(tracesSampleRate) ? tracesSampleRate : 0,
      sendDefaultPii: process.env.SENTRY_SEND_DEFAULT_PII === "true",
    } as any);
  } catch (error) {
    logWarn("Sentry initialization skipped because @sentry/node could not be loaded", {
      error: error instanceof Error ? error.message : String(error),
    });
  }
}
