import { and, asc, eq, gte, lte } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { attendanceRecords, parentStudentLinks, users } from "../core/database/schema/index.js";
import { isMissingRelationError } from "../shared/utils/db-errors.js";
import { HttpError } from "../shared/utils/http-error.js";
import { logWarn } from "../shared/utils/logger.js";

export type AttendanceStatus = "present" | "absent" | "late" | "excused";

export type AttendanceDaily = {
  date: string;
  present: number;
  absent: number;
  late: number;
  excused: number;
};

export type AttendanceSummary = {
  totals: Record<AttendanceStatus, number>;
  daily: AttendanceDaily[];
};

const toDateKey = (value: Date) => value.toISOString().slice(0, 10);

const buildEmptyTotals = (): Record<AttendanceStatus, number> => ({
  present: 0,
  absent: 0,
  late: 0,
  excused: 0,
});

let hasLoggedMissingAttendanceTable = false;

function logMissingAttendanceTableOnce(error: unknown) {
  if (hasLoggedMissingAttendanceTable) return;
  hasLoggedMissingAttendanceTable = true;
  logWarn("Attendance table is missing; attendance summary will return empty data.", {
    code: (error as { code?: string } | undefined)?.code,
    message: (error as { message?: string } | undefined)?.message,
  });
}

export async function getStudentAttendanceSummary(
  studentId: string,
  from: Date,
  to: Date
): Promise<AttendanceSummary> {
  const records = await db
    .select()
    .from(attendanceRecords)
    .where(
      and(
        eq(attendanceRecords.studentId, studentId),
        gte(attendanceRecords.date, from),
        lte(attendanceRecords.date, to)
      )
    )
    .orderBy(asc(attendanceRecords.date))
    .catch((error: unknown) => {
      if (isMissingRelationError(error)) {
        logMissingAttendanceTableOnce(error);
        return [];
      }
      throw error;
    });

  const dailyMap = new Map<string, AttendanceDaily>();
  const totals = buildEmptyTotals();

  for (const record of records) {
    const key = toDateKey(record.date);
    if (!dailyMap.has(key)) {
      dailyMap.set(key, { date: key, ...buildEmptyTotals() });
    }
    const bucket = dailyMap.get(key)!;
    bucket[record.status] += 1;
    totals[record.status] += 1;
  }

  return {
    totals,
    daily: Array.from(dailyMap.values()),
  };
}

export async function getParentAttendanceSummary(parentId: string, from: Date, to: Date) {
  const students = await db
    .select({ id: users.id, name: users.name })
    .from(parentStudentLinks)
    .innerJoin(users, eq(users.id, parentStudentLinks.studentId))
    .where(eq(parentStudentLinks.parentId, parentId));

  return Promise.all(
    students.map(async (student) => ({
      studentId: student.id,
      studentName: student.name,
      summary: await getStudentAttendanceSummary(student.id, from, to),
    }))
  );
}

export async function createAttendanceRecord(input: {
  studentId: string;
  date: Date;
  status: AttendanceStatus;
  notes?: string | null;
}) {
  try {
    const [created] = await db
      .insert(attendanceRecords)
      .values({
        studentId: input.studentId,
        date: input.date,
        status: input.status,
        notes: input.notes ?? null,
      })
      .returning();

    return created;
  } catch (error) {
    if (isMissingRelationError(error)) {
      logMissingAttendanceTableOnce(error);
      throw new HttpError("Attendance feature is not ready yet. Please run database migrations.", 503);
    }
    throw error;
  }
}
