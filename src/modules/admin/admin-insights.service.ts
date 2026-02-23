import { sql } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import { isMissingRelationError } from "../../shared/utils/db-errors.js";
import { logWarn } from "../../shared/utils/logger.js";

export type RoleCounts = {
  student: number;
  parent: number;
  admin: number;
  total: number;
};

export type ActivityDaily = {
  day: string;
  quizAttempts: number;
  assignments: number;
};

export type AttendanceDaily = {
  day: string;
  present: number;
  absent: number;
  late: number;
  excused: number;
};

export type AdminInsights = {
  roles: RoleCounts;
  activity: ActivityDaily[];
  attendance: AttendanceDaily[];
};

const toDayKey = (value: Date) => value.toISOString().slice(0, 10);

const warnedMissingTables = new Set<string>();

const buildDays = (from: Date, to: Date) => {
  const days: string[] = [];
  const cursor = new Date(from);
  while (cursor <= to) {
    days.push(toDayKey(cursor));
    cursor.setDate(cursor.getDate() + 1);
  }
  return days;
};

function logMissingTableOnce(tableName: string, error: unknown) {
  if (warnedMissingTables.has(tableName)) return;
  warnedMissingTables.add(tableName);
  logWarn(`Table '${tableName}' is missing; admin insights will return partial data.`, {
    code: (error as { code?: string } | undefined)?.code,
    message: (error as { message?: string } | undefined)?.message,
  });
}

export async function getAdminInsights(): Promise<AdminInsights> {
  const now = new Date();
  const from = new Date(now);
  from.setDate(from.getDate() - 6);
  from.setHours(0, 0, 0, 0);
  const to = new Date(now);
  to.setHours(23, 59, 59, 999);

  const roleRows = await db.execute(sql`
    SELECT r.name as role, COUNT(u.id)::int as count
    FROM roles r
    LEFT JOIN users u ON u.role_id = r.id
    GROUP BY r.name
  `);

  const roleCounts: RoleCounts = {
    student: 0,
    parent: 0,
    admin: 0,
    total: 0,
  };

  for (const row of roleRows.rows as any[]) {
    const role = String(row.role).toUpperCase();
    const count = Number(row.count ?? 0);
    if (role === "STUDENT") roleCounts.student = count;
    if (role === "PARENT") roleCounts.parent = count;
    if (role === "ADMIN") roleCounts.admin = count;
  }
  roleCounts.total = roleCounts.student + roleCounts.parent + roleCounts.admin;

  const quizRows = await db
    .execute(sql`
      SELECT date_trunc('day', created_at) as day, COUNT(*)::int as count
      FROM quiz_attempts
      WHERE created_at BETWEEN ${from} AND ${to}
      GROUP BY 1
      ORDER BY 1
    `)
    .catch((error: unknown) => {
      if (isMissingRelationError(error)) {
        logMissingTableOnce("quiz_attempts", error);
        return { rows: [] };
      }
      throw error;
    });

  const assignmentRows = await db
    .execute(sql`
      SELECT date_trunc('day', created_at) as day, COUNT(*)::int as count
      FROM assignments
      WHERE created_at BETWEEN ${from} AND ${to}
      GROUP BY 1
      ORDER BY 1
    `)
    .catch((error: unknown) => {
      if (isMissingRelationError(error)) {
        logMissingTableOnce("assignments", error);
        return { rows: [] };
      }
      throw error;
    });

  const attendanceRows = await db
    .execute(sql`
      SELECT date_trunc('day', date) as day, status, COUNT(*)::int as count
      FROM attendance_records
      WHERE date BETWEEN ${from} AND ${to}
      GROUP BY 1, 2
      ORDER BY 1
    `)
    .catch((error: unknown) => {
      if (isMissingRelationError(error)) {
        logMissingTableOnce("attendance_records", error);
        return { rows: [] };
      }
      throw error;
    });

  const dayKeys = buildDays(from, to);
  const activityMap = new Map<string, ActivityDaily>();
  const attendanceMap = new Map<string, AttendanceDaily>();

  for (const key of dayKeys) {
    activityMap.set(key, { day: key, quizAttempts: 0, assignments: 0 });
    attendanceMap.set(key, { day: key, present: 0, absent: 0, late: 0, excused: 0 });
  }

  for (const row of quizRows.rows as any[]) {
    const key = toDayKey(new Date(row.day));
    const entry = activityMap.get(key);
    if (entry) entry.quizAttempts = Number(row.count ?? 0);
  }

  for (const row of assignmentRows.rows as any[]) {
    const key = toDayKey(new Date(row.day));
    const entry = activityMap.get(key);
    if (entry) entry.assignments = Number(row.count ?? 0);
  }

  for (const row of attendanceRows.rows as any[]) {
    const key = toDayKey(new Date(row.day));
    const entry = attendanceMap.get(key);
    if (!entry) continue;
    const status = String(row.status);
    const count = Number(row.count ?? 0);
    if (status === "present") entry.present = count;
    if (status === "absent") entry.absent = count;
    if (status === "late") entry.late = count;
    if (status === "excused") entry.excused = count;
  }

  return {
    roles: roleCounts,
    activity: dayKeys.map((key) => activityMap.get(key)!).filter(Boolean),
    attendance: dayKeys.map((key) => attendanceMap.get(key)!).filter(Boolean),
  };
}
