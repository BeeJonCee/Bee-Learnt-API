import type { Request, Response } from "express";
import { eq, inArray } from "drizzle-orm";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { db } from "../core/database/index.js";
import { modules, neonUsers, roles, subjects, userModuleSelections, users } from "../core/database/schema/index.js";
import { getAnalytics, syncUsersToNeonAuth, checkSchemaConsistency } from "../services/admin.service.js";
import { getAdminInsights } from "../services/admin-insights.service.js";
import { getSystemHealth, getReportStats } from "../services/admin-system.service.js";
import { parseUuid } from "../shared/utils/parse.js";
import type { BeeLearntRole } from "../shared/types/auth.js";

const adminRoles = new Set(["ADMIN", "PARENT", "STUDENT", "TUTOR"]);

export const analytics = asyncHandler(async (_req: Request, res: Response) => {
  const data = await getAnalytics();
  res.json(data);
});

export const insights = asyncHandler(async (_req: Request, res: Response) => {
  const data = await getAdminInsights();
  res.json(data);
});

export const systemHealth = asyncHandler(async (_req: Request, res: Response) => {
  const data = await getSystemHealth();
  res.json(data);
});

export const reportStats = asyncHandler(async (req: Request, res: Response) => {
  const range = (req.query.range as "7d" | "30d" | "90d" | "all") || "7d";
  const data = await getReportStats(range);
  res.json(data);
});

export const generateReport = asyncHandler(async (req: Request, res: Response) => {
  const { type, dateRange, format } = req.body as {
    type: string;
    dateRange: string;
    format: "pdf" | "csv" | "json";
  };

  // In production, this would generate an actual report and store it
  // For now, we'll return a mock download URL
  const timestamp = new Date().toISOString().split("T")[0];
  const filename = `${type}_${dateRange}_${timestamp}`;
  const downloadUrl = `/api/admin/reports/download/${filename}.${format === "pdf" ? "pdf" : format}`;

  res.json({
    filename,
    downloadUrl,
    format,
    generatedAt: new Date().toISOString(),
  });
});

export const listUsers = asyncHandler(async (req: Request, res: Response) => {
  const roleParam = typeof req.query.role === "string" ? req.query.role.toUpperCase() : null;
  const roleFilter = roleParam && adminRoles.has(roleParam) ? roleParam : null;

  const query = db
    .select({
      id: users.id,
      name: users.name,
      email: users.email,
      role: roles.name,
    })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id));

  const rows = roleFilter
    ? await query.where(eq(roles.name, roleFilter as "STUDENT" | "PARENT" | "ADMIN" | "TUTOR"))
    : await query;

  res.json(
    rows.sort((a, b) => a.name.localeCompare(b.name))
  );
});

export const listModules = asyncHandler(async (_req: Request, res: Response) => {
  const rows = await db
    .select({
      id: modules.id,
      title: modules.title,
      grade: modules.grade,
      order: modules.order,
      subjectId: subjects.id,
      subjectName: subjects.name,
    })
    .from(modules)
    .innerJoin(subjects, eq(modules.subjectId, subjects.id))
    .orderBy(subjects.name, modules.grade, modules.order);

  res.json(rows);
});

export const listUserModules = asyncHandler(async (req: Request, res: Response) => {
  const userId = parseUuid(req.params.userId as string);
  if (!userId) {
    res.status(400).json({ message: "Invalid user id" });
    return;
  }

  const rows = await db
    .select({
      moduleId: modules.id,
      title: modules.title,
      grade: modules.grade,
      order: modules.order,
      subjectName: subjects.name,
      status: userModuleSelections.status,
    })
    .from(userModuleSelections)
    .innerJoin(modules, eq(userModuleSelections.moduleId, modules.id))
    .innerJoin(subjects, eq(modules.subjectId, subjects.id))
    .where(eq(userModuleSelections.userId, userId))
    .orderBy(subjects.name, modules.grade, modules.order);

  res.json({ userId, modules: rows });
});

export const assignUserModules = asyncHandler(async (req: Request, res: Response) => {
  const userId = parseUuid(req.params.userId as string);
  if (!userId) {
    res.status(400).json({ message: "Invalid user id" });
    return;
  }

  const { moduleIds } = req.body as { moduleIds: number[] };
  const uniqueModuleIds = Array.from(new Set(moduleIds ?? []));

  const [userRow] = await db
    .select({
      id: users.id,
      role: roles.name,
    })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id))
    .where(eq(users.id, userId))
    .limit(1);

  if (!userRow) {
    res.status(404).json({ message: "User not found" });
    return;
  }

  if (userRow.role !== "STUDENT") {
    res.status(400).json({ message: "Only student modules can be assigned here." });
    return;
  }

  if (uniqueModuleIds.length > 0) {
    const existingModules = await db
      .select({ id: modules.id })
      .from(modules)
      .where(inArray(modules.id, uniqueModuleIds));
    const existingSet = new Set(existingModules.map((row) => row.id));
    const missing = uniqueModuleIds.filter((id) => !existingSet.has(id));
    if (missing.length > 0) {
      res.status(400).json({ message: `Unknown module ids: ${missing.join(", ")}` });
      return;
    }
  }

  const existingSelections = await db
    .select({
      id: userModuleSelections.id,
      moduleId: userModuleSelections.moduleId,
    })
    .from(userModuleSelections)
    .where(eq(userModuleSelections.userId, userId));

  const incomingSet = new Set(uniqueModuleIds);
  const existingByModule = new Map(existingSelections.map((row) => [row.moduleId, row.id]));
  const now = new Date();

  const toUnlockIds = existingSelections
    .filter((row) => incomingSet.has(row.moduleId))
    .map((row) => row.id);
  if (toUnlockIds.length > 0) {
    await db
      .update(userModuleSelections)
      .set({ status: "unlocked", unlockedAt: now })
      .where(inArray(userModuleSelections.id, toUnlockIds));
  }

  const toPendingIds = existingSelections
    .filter((row) => !incomingSet.has(row.moduleId))
    .map((row) => row.id);
  if (toPendingIds.length > 0) {
    await db
      .update(userModuleSelections)
      .set({ status: "pending", unlockedAt: null })
      .where(inArray(userModuleSelections.id, toPendingIds));
  }

  const newModuleIds = uniqueModuleIds.filter((id) => !existingByModule.has(id));
  if (newModuleIds.length > 0) {
    await db.insert(userModuleSelections).values(
      newModuleIds.map((moduleId) => ({
        userId: userId as string,
        moduleId,
        status: "unlocked" as const,
        unlockedAt: now,
      }))
    );
  }

  res.json({ userId, moduleIds: uniqueModuleIds });
});

export const updateUserRole = asyncHandler(async (req: Request, res: Response) => {
  const userId = parseUuid(req.params.userId as string);
  if (!userId) {
    res.status(400).json({ message: "Invalid user id" });
    return;
  }

  const { role } = req.body as { role: string };
  const normalizedRole = role?.toUpperCase();

  if (!normalizedRole || !["STUDENT", "PARENT", "ADMIN", "TUTOR"].includes(normalizedRole)) {
    res.status(400).json({ message: "Invalid role. Must be STUDENT, PARENT, ADMIN, or TUTOR" });
    return;
  }

  const targetRole = normalizedRole as BeeLearntRole;

  // Check if user exists
  const [userRow] = await db
    .select({ id: users.id, email: users.email, name: users.name })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  if (!userRow) {
    res.status(404).json({ message: "User not found" });
    return;
  }

  // Get the role ID
  const [roleRecord] = await db.select().from(roles).where(eq(roles.name, targetRole));
  if (!roleRecord) {
    res.status(500).json({ message: `Role '${targetRole}' not found in database` });
    return;
  }

  // Update BeeLearnt user role
  await db
    .update(users)
    .set({
      roleId: roleRecord.id,
      updatedAt: new Date(),
    })
    .where(eq(users.id, userId));

  // Update Neon Auth user role (sync)
  await db
    .update(neonUsers)
    .set({
      role: targetRole,
      updatedAt: new Date(),
    })
    .where(eq(neonUsers.id, userId));

  res.json({
    userId,
    email: userRow.email,
    name: userRow.name,
    role: targetRole,
    message: "User role updated successfully in both BeeLearnt and Neon Auth",
  });
});

export const getUserDetails = asyncHandler(async (req: Request, res: Response) => {
  const userId = parseUuid(req.params.userId as string);
  if (!userId) {
    res.status(400).json({ message: "Invalid user id" });
    return;
  }

  const [userRow] = await db
    .select({
      id: users.id,
      name: users.name,
      email: users.email,
      image: users.image,
      role: roles.name,
      createdAt: users.createdAt,
      lastLoginAt: users.lastLoginAt,
    })
    .from(users)
    .innerJoin(roles, eq(users.roleId, roles.id))
    .where(eq(users.id, userId))
    .limit(1);

  if (!userRow) {
    res.status(404).json({ message: "User not found" });
    return;
  }

  // Get Neon Auth data
  const [neonUser] = await db
    .select({
      emailVerified: neonUsers.emailVerified,
      banned: neonUsers.banned,
      banReason: neonUsers.banReason,
      role: neonUsers.role,
    })
    .from(neonUsers)
    .where(eq(neonUsers.id, userId))
    .limit(1);

  res.json({
    ...userRow,
    neonAuth: neonUser || null,
  });
});

export const syncSchemaToNeonAuth = asyncHandler(async (_req: Request, res: Response) => {
  const result = await syncUsersToNeonAuth();
  res.json({
    message: "Schema sync completed",
    ...result,
  });
});

export const verifySchemaConsistency = asyncHandler(async (_req: Request, res: Response) => {
  const result = await checkSchemaConsistency();
  res.json(result);
});
