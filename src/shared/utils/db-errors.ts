type PgLikeError = {
  code?: string;
  message?: string;
  error?: string;
  stack?: string;
  cause?: unknown;
  sourceError?: unknown;
  originalError?: unknown;
};

const MISSING_RELATION_CODES = new Set(["42P01", "3F000"]);
const DATABASE_AUTH_CODES = new Set(["28P01", "28000"]);
const DATABASE_AUTH_PATTERNS = [
  "password authentication failed",
  "authentication failed for user",
  "no pg_hba.conf entry",
  "database is closed",
  "the database system is starting up",
];

export function isMissingRelationError(error: unknown) {
  const maybeError = (error ?? {}) as PgLikeError;
  return typeof maybeError.code === "string" && MISSING_RELATION_CODES.has(maybeError.code);
}

export function getMissingRelationName(error: unknown) {
  const message = (error as PgLikeError | undefined)?.message;
  if (typeof message !== "string") return null;

  const match = message.match(/relation "([^"]+)"/i);
  return match?.[1] ?? null;
}

export function isDatabaseAuthError(error: unknown) {
  const queue: unknown[] = [error];
  const visited = new Set<unknown>();

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current || visited.has(current)) continue;
    visited.add(current);

    const maybeError = current as PgLikeError;
    const code = maybeError.code;
    if (typeof code === "string" && DATABASE_AUTH_CODES.has(code)) {
      return true;
    }

    const messageCandidates = [maybeError.message, maybeError.error, maybeError.stack];
    for (const candidate of messageCandidates) {
      const normalized = (candidate ?? "").toString().toLowerCase();
      if (DATABASE_AUTH_PATTERNS.some((pattern) => normalized.includes(pattern))) {
        return true;
      }
    }

    if (maybeError.cause) queue.push(maybeError.cause);
    if (maybeError.sourceError) queue.push(maybeError.sourceError);
    if (maybeError.originalError) queue.push(maybeError.originalError);
  }

  return false;
}
