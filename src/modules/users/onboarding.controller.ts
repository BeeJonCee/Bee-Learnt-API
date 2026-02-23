import type { Request, Response } from "express";
import bcrypt from "bcryptjs";
import { and, eq, gte } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import {
  auditLogs,
  moduleAccessCodes,
  modules,
  subjects,
  userModuleSelections,
} from "../../core/database/schema/index.js";
import { asyncHandler } from "../../core/middleware/async-handler.js";
import { sendTokenEmail } from "../../shared/email/send-token.js";
import { logModule, logToken } from "../../shared/audit/audit-log.js";
import { HttpError } from "../../shared/utils/http-error.js";
import { getDailyAccessCode, isDailyAccessCodeMatch } from "../../shared/utils/access-codes.js";

export const listModules = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const [moduleRows, selectionRows] = await Promise.all([
    db
      .select({
        id: modules.id,
        title: modules.title,
        grade: modules.grade,
        order: modules.order,
        subjectName: subjects.name,
      })
      .from(modules)
      .innerJoin(subjects, eq(modules.subjectId, subjects.id))
      .orderBy(subjects.name, modules.grade, modules.order),
    db.select().from(userModuleSelections).where(eq(userModuleSelections.userId, userId)),
  ]);

  const selectionMap = new Map(
    selectionRows.map((selection) => [selection.moduleId, selection.status])
  );

  res.json({
    modules: moduleRows.map((module) => ({
      ...module,
      selected: selectionMap.has(module.id),
      status: selectionMap.get(module.id) ?? null,
    })),
  });
});

export const selectModule = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const { moduleId, code } = req.body as { moduleId: number; code: string };

  const [moduleRow] = await db
    .select({ id: modules.id, grade: modules.grade, order: modules.order })
    .from(modules)
    .where(eq(modules.id, moduleId));

  if (!moduleRow) {
    throw new HttpError("Module not found", 404);
  }

  const [existingUnlocked] = await db
    .select({ id: userModuleSelections.id })
    .from(userModuleSelections)
    .where(and(eq(userModuleSelections.userId, userId), eq(userModuleSelections.status, "unlocked")))
    .limit(1);

  const [codeRow] = await db
    .select()
    .from(moduleAccessCodes)
    .where(and(eq(moduleAccessCodes.moduleId, moduleId), eq(moduleAccessCodes.active, true)));

  const dailyMatch = isDailyAccessCodeMatch({
    code,
    moduleId: moduleRow.id,
    grade: moduleRow.grade,
    order: moduleRow.order,
  });
  const storedMatch = codeRow ? await bcrypt.compare(code, codeRow.codeHash) : false;

  const valid = existingUnlocked ? dailyMatch || storedMatch : dailyMatch;
  if (!valid) {
    throw new HttpError("Invalid access code for today", 403);
  }

  const [existing] = await db
    .select()
    .from(userModuleSelections)
    .where(and(eq(userModuleSelections.userId, userId), eq(userModuleSelections.moduleId, moduleId)));

  if (existing) {
    const [updated] = await db
      .update(userModuleSelections)
      .set({ status: "unlocked", unlockedAt: new Date() })
      .where(eq(userModuleSelections.id, existing.id))
      .returning();
    res.json({ moduleId, status: updated.status });
    return;
  }

  const [created] = await db
    .insert(userModuleSelections)
    .values({
      userId,
      moduleId,
      status: "unlocked",
      unlockedAt: new Date(),
    })
    .returning();

  res.status(201).json({ moduleId, status: created.status });
});

function getUtcDayEnd(date: Date) {
  return new Date(
    Date.UTC(
      date.getUTCFullYear(),
      date.getUTCMonth(),
      date.getUTCDate() + 1,
      0,
      0,
      0,
      0
    )
  );
}

function getUtcDayStart(date: Date) {
  return new Date(
    Date.UTC(
      date.getUTCFullYear(),
      date.getUTCMonth(),
      date.getUTCDate(),
      0,
      0,
      0,
      0
    )
  );
}

export const requestModuleCode = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const { moduleId } = req.body as { moduleId: number };

  const [moduleRow] = await db
    .select({
      id: modules.id,
      title: modules.title,
      grade: modules.grade,
      order: modules.order,
    })
    .from(modules)
    .where(eq(modules.id, moduleId));

  if (!moduleRow) {
    throw new HttpError("Module not found", 404);
  }

  const dailyCode = getDailyAccessCode({
    moduleId: moduleRow.id,
    grade: moduleRow.grade,
    order: moduleRow.order,
  });
  const now = new Date();
  const dayStart = getUtcDayStart(now);
  const expiresAt = getUtcDayEnd(now);

  await logModule(
    "module.unlock_request",
    userId,
    moduleRow.id,
    { requestedByRole: req.user?.role ?? null },
    req
  );

  const [existingSentToday] = await db
    .select({ id: auditLogs.id })
    .from(auditLogs)
    .where(
      and(
        eq(auditLogs.actorId, userId),
        eq(auditLogs.action, "token.email_sent"),
        eq(auditLogs.entity, "token"),
        eq(auditLogs.entityId, moduleRow.id),
        gte(auditLogs.createdAt, dayStart)
      )
    )
    .limit(1);

  if (existingSentToday) {
    res.status(200).json({
      moduleId: moduleRow.id,
      message: "Access code already sent to admin today",
      expiresAt,
      alreadySent: true,
    });
    return;
  }

  const emailResult = await sendTokenEmail({
    moduleName: moduleRow.title,
    moduleId: moduleRow.id,
    token: dailyCode,
    studentName: req.user?.name ?? req.user?.email ?? "Student",
    requestedBy: req.user?.name ?? req.user?.email ?? "Student",
    expiresAt,
  });

  if (!emailResult.success) {
    await logModule(
      "module.unlock_failure",
      userId,
      moduleRow.id,
      {
        via: "onboarding",
        reason: emailResult.error ?? "email_send_failed",
      },
      req
    );

    res.status(202).json({
      moduleId: moduleRow.id,
      message:
        "Access code generated, but admin email delivery is not configured yet. Please ask support to configure SMTP credentials.",
      expiresAt,
      alreadySent: false,
      emailSent: false,
    });
    return;
  }

  await logToken(
    "token.email_sent",
    userId,
    moduleRow.id,
    { via: "onboarding", emailMessageId: emailResult.messageId ?? null },
    req
  );

  res.status(201).json({
    moduleId: moduleRow.id,
    message: "Access code sent to admin",
    expiresAt,
    alreadySent: false,
    emailSent: true,
  });
});
