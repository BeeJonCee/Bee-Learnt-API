import "./instrument.js";
import express from "express";
import cors from "cors";
import swaggerUi from "swagger-ui-express";
import * as Sentry from "@sentry/node";
import { env } from "./config/env.js";
import { specs } from "./config/swagger.js";
import { authenticate } from "./core/middleware/auth.js";
import { errorHandler } from "./core/middleware/error-handler.js";
import { notFound } from "./core/middleware/not-found.js";
import { router } from "./routes/index.js";

const app = express();

// ─── CORS ──────────────────────────────────────────────────────────
const corsOrigin =
  env.corsOrigin === "*"
    ? "*"
    : env.corsOrigin.split(",").map((origin) => origin.trim());

app.use(cors({ origin: corsOrigin, credentials: env.corsOrigin !== "*" }));

// ─── Body Parsing ──────────────────────────────────────────────────
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// ─── Swagger Documentation ─────────────────────────────────────────
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs, { explorer: true }));

// ─── Health Check ──────────────────────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "bee-learnt-api" });
});

app.get("/", (_req, res) => {
  res.json({ message: "BeeLearnt API" });
});

// ─── Sentry Debug (dev/staging) ────────────────────────────────────
app.get("/debug-sentry", () => {
  throw new Error("Sentry test error!");
});

// ─── Authentication Middleware (sets req.user) ─────────────────────
app.use(authenticate);

// ─── API Routes ────────────────────────────────────────────────────
app.use("/api", router);

// ─── 404 Handler ───────────────────────────────────────────────────
app.use(notFound);

// ─── Sentry Error Handler (must be before custom errorHandler) ─────
Sentry.setupExpressErrorHandler(app);

// ─── Custom Error Handler ──────────────────────────────────────────
app.use(errorHandler);

export { app };
