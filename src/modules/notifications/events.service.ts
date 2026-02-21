import { and, desc, eq, gte, lte, or, type SQL } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import { events } from "../../core/database/schema/index.js";
import type { BeeLearntRole } from "../../shared/types/auth.js";
import { isMissingRelationError } from "../../shared/utils/db-errors.js";
import { HttpError } from "../../shared/utils/http-error.js";
import { logWarn } from "../../shared/utils/logger.js";

export type EventInput = {
  title: string;
  description: string;
  startAt: string;
  endAt?: string | null;
  allDay?: boolean;
  location?: string | null;
  audience: "ALL" | BeeLearntRole;
};

export type EventFilters = {
  role: BeeLearntRole;
  limit?: number;
  from?: Date | null;
  to?: Date | null;
};

let hasLoggedMissingEventsTable = false;

function logMissingEventsTableOnce(error: unknown) {
  if (hasLoggedMissingEventsTable) return;
  hasLoggedMissingEventsTable = true;
  logWarn("Events table is missing; returning empty events list until migrations are applied.", {
    code: (error as { code?: string } | undefined)?.code,
    message: (error as { message?: string } | undefined)?.message,
  });
}

export async function listEvents({ role, limit = 6, from, to }: EventFilters) {
  const conditions: SQL<any>[] = [or(eq(events.audience, "ALL"), eq(events.audience, role)) as SQL<any>];

  if (from) {
    conditions.push(gte(events.startAt, from));
  }
  if (to) {
    conditions.push(lte(events.startAt, to));
  }

  const whereClause = conditions.length ? and(...conditions) : undefined;
  
  try {
    if (whereClause) {
      return db.select().from(events).where(whereClause).orderBy(desc(events.startAt)).limit(limit);
    }

    return db.select().from(events).orderBy(desc(events.startAt)).limit(limit);
  } catch (error) {
    if (isMissingRelationError(error)) {
      logMissingEventsTableOnce(error);
      return [];
    }
    throw error;
  }
}

export async function createEvent(input: EventInput) {
  try {
    const [created] = await db
      .insert(events)
      .values({
        title: input.title,
        description: input.description,
        startAt: new Date(input.startAt),
        endAt: input.endAt ? new Date(input.endAt) : null,
        allDay: input.allDay ?? false,
        location: input.location ?? null,
        audience: input.audience,
      })
      .returning();

    return created;
  } catch (error) {
    if (isMissingRelationError(error)) {
      logMissingEventsTableOnce(error);
      throw new HttpError("Events feature is not ready yet. Please run database migrations.", 503);
    }
    throw error;
  }
}
