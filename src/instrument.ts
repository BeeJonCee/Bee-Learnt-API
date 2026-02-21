import * as Sentry from "@sentry/node";

const tracesSampleRate = Number(process.env.SENTRY_TRACES_SAMPLE_RATE ?? "0");

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.SENTRY_ENVIRONMENT ?? process.env.NODE_ENV ?? "development",
  tracesSampleRate: Number.isFinite(tracesSampleRate) ? tracesSampleRate : 0,
  sendDefaultPii: process.env.SENTRY_SEND_DEFAULT_PII === "true",
});
