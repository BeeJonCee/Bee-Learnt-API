import crypto from "crypto";
import { and, desc, eq, gt, isNull } from "drizzle-orm";
import { db } from "../../core/database/index.js";
import { emailVerificationCodes } from "../../core/database/schema/index.js";
import { sendTwoFactorCodeEmail } from "../../shared/email/send-two-factor.js";
import { HttpError } from "../../shared/utils/http-error.js";

const TWO_FACTOR_EXPIRY_MINUTES = 10;

function normalizeEmail(value: string) {
  return value.trim().toLowerCase();
}

function generateCode() {
  return crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");
}

function hashCode(email: string, code: string) {
  return crypto
    .createHash("sha256")
    .update(`${normalizeEmail(email)}:${code}`)
    .digest("hex");
}

function maskEmail(email: string) {
  const parts = email.split("@");
  if (parts.length !== 2) return "***";
  const [local, domain] = parts;
  if (local.length <= 2) return `***@${domain}`;
  return `${local.slice(0, 2)}***@${domain}`;
}

export async function sendTwoFactorChallenge(input: {
  email: string;
  purpose: "login" | "register" | "social";
}) {
  const email = normalizeEmail(input.email);
  const code = generateCode();
  const codeHash = hashCode(email, code);
  const expiresAt = new Date(Date.now() + TWO_FACTOR_EXPIRY_MINUTES * 60_000);

  console.info(`[two-factor] DEV CODE for ${maskEmail(email)} [${input.purpose}]: ${code}`);

  await db.insert(emailVerificationCodes).values({
    email,
    codeHash,
    expiresAt,
  });

  try {
    await sendTwoFactorCodeEmail({
      toEmail: email,
      code,
      expiresInMinutes: TWO_FACTOR_EXPIRY_MINUTES,
      purpose: input.purpose,
    });
  } catch (error) {
    throw new HttpError(
      error instanceof Error
        ? `Failed to send verification code: ${error.message}`
        : "Failed to send verification code",
      503,
    );
  }

  return {
    requiresTwoFactor: true as const,
    factorType: "email" as const,
    maskedEmail: maskEmail(email),
    expiresInSeconds: TWO_FACTOR_EXPIRY_MINUTES * 60,
    message: "Verification code sent to your email address.",
  };
}

export async function verifyTwoFactorCode(input: { email: string; code: string }) {
  const email = normalizeEmail(input.email);
  const code = input.code.trim();

  if (!/^\d{6}$/.test(code)) {
    return { valid: false as const };
  }

  const now = new Date();
  const [activeCode] = await db
    .select()
    .from(emailVerificationCodes)
    .where(
      and(
        eq(emailVerificationCodes.email, email),
        isNull(emailVerificationCodes.consumedAt),
        gt(emailVerificationCodes.expiresAt, now),
      ),
    )
    .orderBy(desc(emailVerificationCodes.createdAt))
    .limit(1);

  if (!activeCode) {
    return { valid: false as const };
  }

  const expectedHash = hashCode(email, code);
  if (activeCode.codeHash !== expectedHash) {
    return { valid: false as const };
  }

  await db
    .update(emailVerificationCodes)
    .set({ consumedAt: new Date() })
    .where(eq(emailVerificationCodes.id, activeCode.id));

  return { valid: true as const };
}

