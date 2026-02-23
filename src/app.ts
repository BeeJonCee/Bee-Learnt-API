import "./instrument.js";
import express from "express";
import cors from "cors";
import swaggerUi from "swagger-ui-express";
import { env } from "./config/env.js";
import { specs } from "./config/swagger.js";
import { authenticate } from "./core/middleware/auth.js";
import { errorHandler } from "./core/middleware/error-handler.js";
import { notFound } from "./core/middleware/not-found.js";
import { requestLogger } from "./core/middleware/request-logger.js";
import { router } from "./modules/index.js";
import { createLogger } from "./shared/utils/logger.js";

const appLogger = createLogger("app");

const app = express();

// â”€â”€â”€ Request Logging â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use(requestLogger);

// â”€â”€â”€ CORS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const corsOrigin =
  env.corsOrigin === "*"
    ? "*"
    : env.corsOrigin.split(",").map((origin) => origin.trim());

app.use(cors({ origin: corsOrigin, credentials: env.corsOrigin !== "*" }));

// â”€â”€â”€ Body Parsing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// â”€â”€â”€ Swagger Documentation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs, { explorer: true }));

// â”€â”€â”€ Health Check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "bee-learnt-api" });
});

app.get("/", (_req, res) => {
  res.json({ message: "BeeLearnt API" });
});

// â”€â”€â”€ Sentry Debug (dev/staging) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get("/debug-sentry", () => {
  throw new Error("Sentry test error!");
});

// â”€â”€â”€ Authentication Middleware (sets req.user) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use(authenticate);

// â”€â”€â”€ API Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use("/api", router);

// â”€â”€â”€ 404 Handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use(notFound);

// â”€â”€â”€ Sentry Error Handler (must be before custom errorHandler) â”€â”€â”€â”€â”€
if (process.env.SENTRY_DSN) {
  try {
    const Sentry = await import("@sentry/node");
    Sentry.setupExpressErrorHandler(app);
  } catch (error) {
    appLogger.warn("Sentry error handler skipped — @sentry/node could not be loaded", {
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

// â”€â”€â”€ Custom Error Handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use(errorHandler);

export { app };
