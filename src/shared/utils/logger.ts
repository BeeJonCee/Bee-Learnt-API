/**
 * BeeLearnt API — Structured Logger
 *
 * Features:
 *  - Five levels: debug | info | warn | error | fatal
 *  - Dev: timestamped, ANSI-coloured, pretty-printed to stdout/stderr
 *  - Prod: single-line JSON to stdout/stderr (log-drain friendly)
 *  - AsyncLocalStorage: every log call inside a request automatically
 *    includes { requestId, userId } with zero boilerplate
 *  - createLogger(context) factory — module/service-scoped child loggers
 *  - Backward-compatible logInfo / logWarn / logError exports
 *  - LOG_LEVEL env var (default: "debug" in dev, "info" in prod)
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";

// ─── Types ─────────────────────────────────────────────────────────────────────

export type LogLevel = "debug" | "info" | "warn" | "error" | "fatal";

export type LogMeta = Record<string, unknown>;

export interface RequestContext {
  requestId: string;
  method?: string;
  path?: string;
  userId?: string;
}

export interface Logger {
  debug(message: string, meta?: LogMeta): void;
  info(message: string, meta?: LogMeta): void;
  warn(message: string, meta?: LogMeta): void;
  error(message: string, meta?: LogMeta): void;
  fatal(message: string, meta?: LogMeta): void;
  /** Create a child logger that inherits the same context with extra fields */
  child(extra: LogMeta): Logger;
}

// ─── Request context (AsyncLocalStorage) ─────────────────────────────────────

export const requestContextStore = new AsyncLocalStorage<RequestContext>();

/** Create a new request context object (used by the request-logger middleware). */
export function createRequestContext(
  method: string,
  path: string,
  userId?: string
): RequestContext {
  return { requestId: randomUUID(), method, path, userId };
}

/** Get the request context from the current async scope (if inside a request). */
export function getRequestContext(): RequestContext | undefined {
  return requestContextStore.getStore();
}

// ─── Level configuration ──────────────────────────────────────────────────────

const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  fatal: 50,
};

const isDev = (process.env.NODE_ENV ?? "development") !== "production";

function resolveMinLevel(): number {
  const envLevel = process.env.LOG_LEVEL as LogLevel | undefined;
  if (envLevel && envLevel in LEVEL_RANK) return LEVEL_RANK[envLevel];
  return isDev ? LEVEL_RANK.debug : LEVEL_RANK.info;
}

// Evaluate once at module load; mutations to LOG_LEVEL after startup are ignored.
let MIN_LEVEL = resolveMinLevel();

/** Override the minimum log level at runtime (useful in tests). */
export function setLogLevel(level: LogLevel): void {
  MIN_LEVEL = LEVEL_RANK[level];
}

// ─── ANSI colours ────────────────────────────────────────────────────────────

const C = {
  reset:   "\x1b[0m",
  bold:    "\x1b[1m",
  dim:     "\x1b[2m",
  grey:    "\x1b[90m",
  green:   "\x1b[32m",
  cyan:    "\x1b[36m",
  yellow:  "\x1b[33m",
  red:     "\x1b[31m",
  magenta: "\x1b[35m",
  blue:    "\x1b[34m",
  white:   "\x1b[37m",
} as const;

const LEVEL_COLOR: Record<LogLevel, string> = {
  debug: C.grey,
  info:  C.green,
  warn:  C.yellow,
  error: C.red,
  fatal: C.magenta,
};

// Fixed-width labels keep columns aligned in the terminal.
const LEVEL_LABEL: Record<LogLevel, string> = {
  debug: "DEBUG",
  info:  " INFO",
  warn:  " WARN",
  error: "ERROR",
  fatal: "FATAL",
};

// ─── Core write ───────────────────────────────────────────────────────────────

function ts(): string {
  return new Date().toISOString();
}

function writeLog(
  level: LogLevel,
  context: string,
  message: string,
  extraMeta?: LogMeta,
  childMeta?: LogMeta,
): void {
  if (LEVEL_RANK[level] < MIN_LEVEL) return;

  // Merge request context + child fields + call-site meta (later wins)
  const reqCtx = requestContextStore.getStore();
  const merged: LogMeta = {
    ...(reqCtx?.requestId ? { requestId: reqCtx.requestId } : {}),
    ...(reqCtx?.userId    ? { userId:    reqCtx.userId }    : {}),
    ...childMeta,
    ...extraMeta,
  };
  const hasMeta = Object.keys(merged).length > 0;

  if (isDev) {
    // ── Pretty dev format ─────────────────────────────────────────────────────
    const timestamp  = `${C.grey}${ts()}${C.reset}`;
    const levelStr   = `${LEVEL_COLOR[level]}${C.bold}${LEVEL_LABEL[level]}${C.reset}`;
    const contextStr = context
      ? `${C.cyan}[${context}]${C.reset}`
      : "";
    const messageStr = `${C.white}${message}${C.reset}`;
    const metaStr    = hasMeta
      ? ` ${C.dim}${JSON.stringify(merged)}${C.reset}`
      : "";

    const line = `${timestamp} ${levelStr} ${contextStr} ${messageStr}${metaStr}\n`;

    if (level === "error" || level === "fatal") {
      process.stderr.write(line);
    } else {
      process.stdout.write(line);
    }
  } else {
    // ── Structured JSON (production / log drain) ──────────────────────────────
    const entry = JSON.stringify({
      timestamp: ts(),
      level,
      context: context || undefined,
      message,
      ...(hasMeta ? merged : {}),
    });

    if (level === "error" || level === "fatal") {
      process.stderr.write(entry + "\n");
    } else {
      process.stdout.write(entry + "\n");
    }
  }
}

// ─── Logger factory ───────────────────────────────────────────────────────────

/**
 * Create a named logger for a module, service, or subsystem.
 *
 * @example
 * ```ts
 * const logger = createLogger("auth");
 * logger.info("User logged in", { userId });
 * ```
 */
export function createLogger(context: string, parentMeta?: LogMeta): Logger {
  const logger: Logger = {
    debug: (message, meta) => writeLog("debug", context, message, meta, parentMeta),
    info:  (message, meta) => writeLog("info",  context, message, meta, parentMeta),
    warn:  (message, meta) => writeLog("warn",  context, message, meta, parentMeta),
    error: (message, meta) => writeLog("error", context, message, meta, parentMeta),
    fatal: (message, meta) => writeLog("fatal", context, message, meta, parentMeta),
    child: (extra) => createLogger(context, { ...parentMeta, ...extra }),
  };
  return logger;
}

// ─── Root / system logger ─────────────────────────────────────────────────────

const systemLogger = createLogger("system");

// ─── Backward-compatible function exports ─────────────────────────────────────
// Existing files (bootstrap.ts, error-handler.ts, etc.) call these directly.
// They all route through the system logger so output is identical in format.

export function logDebug(message: string, meta?: LogMeta): void {
  systemLogger.debug(message, meta);
}

export function logInfo(message: string, meta?: LogMeta): void {
  systemLogger.info(message, meta);
}

export function logWarn(message: string, meta?: LogMeta): void {
  systemLogger.warn(message, meta);
}

export function logError(message: string, meta?: LogMeta): void {
  systemLogger.error(message, meta);
}

export function logFatal(message: string, meta?: LogMeta): void {
  systemLogger.fatal(message, meta);
}
