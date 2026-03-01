import crypto from "crypto";
import { and, asc, desc, eq, gt, isNull, sql } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import { authVerificationCodes } from "../../core/database/schema/index.js";
import { sendVerificationOtpEmail } from "../../shared/email/send-two-factor.js";
import { logAudit } from "../../shared/audit/audit-log.js";
import { isE164Phone, maskPhone, normalizeSAPhone } from "../../shared/utils/phone.js";
import { sendOtpSmsViaNovu } from "../../shared/utils/novu.js";
import { HttpError } from "../../shared/utils/http-error.js";

export type VerificationChannel = "email" | "sms";
export type VerificationPurpose = "email_verification" | "phone_verification";

const OTP_EXPIRY_MINUTES = 10;
const OTP_SEND_WINDOW_MS = 15 * 60 * 1000;
const OTP_SEND_MAX = 3;
const OTP_VERIFY_WINDOW_MS = 10 * 60 * 1000;
const OTP_VERIFY_MAX_ATTEMPTS = 5;

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

export function normalizeVerificationTarget(
  channel: VerificationChannel,
  target: string,
): string {
  if (channel === "email") {
    return normalizeEmail(target);
  }

  const normalized = normalizeSAPhone(target);
  if (!isE164Phone(normalized)) {
    throw new HttpError("Phone target must be E.164 format, e.g. +27821234567", 400);
  }
  return normalized;
}

export function maskVerificationTarget(
  channel: VerificationChannel,
  target: string,
): string {
  if (channel === "email") {
    const parts = target.split("@");
    if (parts.length !== 2) return "***";
    const [local, domain] = parts;
    if (local.length <= 2) return `***@${domain}`;
    return `${local.slice(0, 2)}***@${domain}`;
  }

  return maskPhone(target);
}

function generateOtpCode(): string {
  return crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");
}

function hashOtpCode(channel: VerificationChannel, target: string, code: string): string {
  return crypto
    .createHash("sha256")
    .update(`${channel}:${target}:${code}`)
    .digest("hex");
}

function isTimingSafeEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

async function getSendLimitState(input: {
  channel: VerificationChannel;
  target: string;
}): Promise<{ limited: boolean; cooldownSeconds: number }> {
  const windowStart = new Date(Date.now() - OTP_SEND_WINDOW_MS);

  const [countRow] = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(authVerificationCodes)
    .where(
      and(
        eq(authVerificationCodes.channel, input.channel),
        eq(authVerificationCodes.target, input.target),
        gt(authVerificationCodes.createdAt, windowStart),
      ),
    );

  const sentCount = Number(countRow?.count ?? 0);
  if (sentCount < OTP_SEND_MAX) {
    return { limited: false, cooldownSeconds: 0 };
  }

  const [oldest] = await db
    .select({ createdAt: authVerificationCodes.createdAt })
    .from(authVerificationCodes)
    .where(
      and(
        eq(authVerificationCodes.channel, input.channel),
        eq(authVerificationCodes.target, input.target),
        gt(authVerificationCodes.createdAt, windowStart),
      ),
    )
    .orderBy(asc(authVerificationCodes.createdAt))
    .limit(1);

  const cooldownMs = oldest?.createdAt
    ? oldest.createdAt.getTime() + OTP_SEND_WINDOW_MS - Date.now()
    : OTP_SEND_WINDOW_MS;

  return {
    limited: true,
    cooldownSeconds: Math.max(1, Math.ceil(cooldownMs / 1000)),
  };
}

async function getAttemptState(input: {
  channel: VerificationChannel;
  target: string;
}): Promise<{ locked: boolean; remainingAttempts: number; cooldownSeconds: number }> {
  const windowStart = new Date(Date.now() - OTP_VERIFY_WINDOW_MS);

  const [attemptsRow] = await db
    .select({
      attempts:
        sql<number>`coalesce(sum(${authVerificationCodes.attempts}), 0)::int`,
    })
    .from(authVerificationCodes)
    .where(
      and(
        eq(authVerificationCodes.channel, input.channel),
        eq(authVerificationCodes.target, input.target),
        gt(authVerificationCodes.createdAt, windowStart),
      ),
    );

  const attempts = Number(attemptsRow?.attempts ?? 0);
  if (attempts < OTP_VERIFY_MAX_ATTEMPTS) {
    return {
      locked: false,
      remainingAttempts: OTP_VERIFY_MAX_ATTEMPTS - attempts,
      cooldownSeconds: 0,
    };
  }

  const [oldestAttempted] = await db
    .select({ createdAt: authVerificationCodes.createdAt })
    .from(authVerificationCodes)
    .where(
      and(
        eq(authVerificationCodes.channel, input.channel),
        eq(authVerificationCodes.target, input.target),
        gt(authVerificationCodes.createdAt, windowStart),
      ),
    )
    .orderBy(asc(authVerificationCodes.createdAt))
    .limit(1);

  const cooldownMs = oldestAttempted?.createdAt
    ? oldestAttempted.createdAt.getTime() + OTP_VERIFY_WINDOW_MS - Date.now()
    : OTP_VERIFY_WINDOW_MS;

  return {
    locked: true,
    remainingAttempts: 0,
    cooldownSeconds: Math.max(1, Math.ceil(cooldownMs / 1000)),
  };
}

export async function sendVerificationCode(input: {
  userId?: string | null;
  channel: VerificationChannel;
  purpose: VerificationPurpose;
  target: string;
}): Promise<{
  channel: VerificationChannel;
  maskedTarget: string;
  expiresInSeconds: number;
  cooldownSeconds: number;
}> {
  const normalizedTarget = normalizeVerificationTarget(input.channel, input.target);
  const maskedTarget = maskVerificationTarget(input.channel, normalizedTarget);

  const sendLimitState = await getSendLimitState({
    channel: input.channel,
    target: normalizedTarget,
  });
  if (sendLimitState.limited) {
    throw new HttpError(
      `Too many verification requests. Try again in ${sendLimitState.cooldownSeconds} seconds.`,
      429,
    );
  }

  const code = generateOtpCode();
  const codeHash = hashOtpCode(input.channel, normalizedTarget, code);
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60_000);

  await db.insert(authVerificationCodes).values({
    userId: input.userId ?? null,
    channel: input.channel,
    purpose: input.purpose,
    target: normalizedTarget,
    codeHash,
    expiresAt,
    attempts: 0,
    lastSentAt: new Date(),
  });

  if (input.channel === "email") {
    await sendVerificationOtpEmail({
      toEmail: normalizedTarget,
      code,
      expiresInMinutes: OTP_EXPIRY_MINUTES,
    });
    await logAudit({
      actorId: input.userId ?? null,
      action: "otp_sent_email",
      entity: "user",
      details: { channel: input.channel, target: maskedTarget, purpose: input.purpose },
    });
  } else {
    const smsResult = await sendOtpSmsViaNovu({
      subscriberId: input.userId ?? normalizedTarget,
      phone: normalizedTarget,
      code,
      expiresInMinutes: OTP_EXPIRY_MINUTES,
    });

    if (!smsResult.sent) {
      await logAudit({
        actorId: input.userId ?? null,
        action: "otp_sent_sms",
        entity: "user",
        details: {
          channel: input.channel,
          target: maskedTarget,
          purpose: input.purpose,
          delivered: false,
          reason: smsResult.reason ?? "Unknown Novu error",
        },
      });
      throw new HttpError("Failed to send SMS verification code.", 503);
    }

    await logAudit({
      actorId: input.userId ?? null,
      action: "otp_sent_sms",
      entity: "user",
      details: {
        channel: input.channel,
        target: maskedTarget,
        purpose: input.purpose,
        delivered: true,
      },
    });
  }

  return {
    channel: input.channel,
    maskedTarget,
    expiresInSeconds: OTP_EXPIRY_MINUTES * 60,
    cooldownSeconds: Math.ceil(OTP_SEND_WINDOW_MS / 1000),
  };
}

export async function verifyVerificationCode(input: {
  channel: VerificationChannel;
  target: string;
  code: string;
}): Promise<{
  valid: boolean;
  userId: string | null;
  cooldownSeconds?: number;
}> {
  const normalizedTarget = normalizeVerificationTarget(input.channel, input.target);
  const attemptState = await getAttemptState({
    channel: input.channel,
    target: normalizedTarget,
  });

  if (attemptState.locked) {
    return {
      valid: false,
      userId: null,
      cooldownSeconds: attemptState.cooldownSeconds,
    };
  }

  const now = new Date();
  const [activeCode] = await db
    .select({
      id: authVerificationCodes.id,
      userId: authVerificationCodes.userId,
      codeHash: authVerificationCodes.codeHash,
      attempts: authVerificationCodes.attempts,
    })
    .from(authVerificationCodes)
    .where(
      and(
        eq(authVerificationCodes.channel, input.channel),
        eq(authVerificationCodes.target, normalizedTarget),
        isNull(authVerificationCodes.consumedAt),
        gt(authVerificationCodes.expiresAt, now),
      ),
    )
    .orderBy(desc(authVerificationCodes.createdAt))
    .limit(1);

  if (!activeCode) {
    return { valid: false, userId: null };
  }

  const expectedHash = hashOtpCode(input.channel, normalizedTarget, input.code.trim());
  const valid = isTimingSafeEqual(activeCode.codeHash, expectedHash);

  if (!valid) {
    await db
      .update(authVerificationCodes)
      .set({
        attempts: sql`${authVerificationCodes.attempts} + 1`,
      })
      .where(eq(authVerificationCodes.id, activeCode.id));

    return { valid: false, userId: activeCode.userId ?? null };
  }

  await db
    .update(authVerificationCodes)
    .set({ consumedAt: now })
    .where(
      and(
        eq(authVerificationCodes.channel, input.channel),
        eq(authVerificationCodes.target, normalizedTarget),
        isNull(authVerificationCodes.consumedAt),
      ),
    );

  await logAudit({
    actorId: activeCode.userId ?? null,
    action: input.channel === "email" ? "otp_verified_email" : "otp_verified_phone",
    entity: "user",
    details: {
      channel: input.channel,
      target: maskVerificationTarget(input.channel, normalizedTarget),
    },
  });

  return { valid: true, userId: activeCode.userId ?? null };
}

export async function getLatestVerificationCode(input: {
  channel: VerificationChannel;
  target: string;
}) {
  const normalizedTarget = normalizeVerificationTarget(input.channel, input.target);

  const [latest] = await db
    .select({
      id: authVerificationCodes.id,
      userId: authVerificationCodes.userId,
      target: authVerificationCodes.target,
      channel: authVerificationCodes.channel,
      purpose: authVerificationCodes.purpose,
      expiresAt: authVerificationCodes.expiresAt,
      consumedAt: authVerificationCodes.consumedAt,
      createdAt: authVerificationCodes.createdAt,
    })
    .from(authVerificationCodes)
    .where(
      and(
        eq(authVerificationCodes.channel, input.channel),
        eq(authVerificationCodes.target, normalizedTarget),
      ),
    )
    .orderBy(desc(authVerificationCodes.createdAt))
    .limit(1);

  return latest ?? null;
}

export async function consumeVerificationCodesForTarget(input: {
  channel: VerificationChannel;
  target: string;
}): Promise<void> {
  const normalizedTarget = normalizeVerificationTarget(input.channel, input.target);

  await db
    .update(authVerificationCodes)
    .set({ consumedAt: new Date() })
    .where(
      and(
        eq(authVerificationCodes.channel, input.channel),
        eq(authVerificationCodes.target, normalizedTarget),
        isNull(authVerificationCodes.consumedAt),
      ),
    );
}
