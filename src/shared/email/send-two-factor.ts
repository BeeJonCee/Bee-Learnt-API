import { Resend } from "resend";
import { env } from "../../config/env.js";

const APP_NAME = "BeeLearnt";
const FROM_EMAIL = env.fromEmail || "noreply@beeintelligence.tech";

function getResend() {
  if (!env.resendApiKey) {
    throw new Error("RESEND_API_KEY is not configured");
  }
  return new Resend(env.resendApiKey);
}

export async function sendPasswordResetEmail(input: {
  toEmail: string;
  resetUrl: string;
  expiresInMinutes: number;
}): Promise<void> {
  const resend = getResend();

  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;line-height:1.6;color:#111827;">
      <h2 style="margin-bottom:8px;">${APP_NAME} – Password Reset</h2>
      <p>We received a request to reset your password. Click the button below to choose a new one:</p>
      <a href="${input.resetUrl}"
         style="display:inline-block;padding:12px 24px;background:#f6c945;color:#000;text-decoration:none;border-radius:6px;font-weight:600;margin:16px 0;">
        Reset my password
      </a>
      <p style="margin-top:16px;">This link expires in ${input.expiresInMinutes} minutes.</p>
      <p style="color:#6b7280;">If you did not request a password reset, you can safely ignore this email.</p>
    </div>
  `;

  const text = [
    `${APP_NAME} – Password Reset`,
    "",
    "We received a request to reset your password.",
    "Open the link below to choose a new one:",
    input.resetUrl,
    "",
    `Link expires in ${input.expiresInMinutes} minutes.`,
    "If you did not request a password reset, ignore this email.",
  ].join("\n");

  const { error } = await resend.emails.send({
    from: `${APP_NAME} <${FROM_EMAIL}>`,
    to: input.toEmail,
    subject: `${APP_NAME}: Reset your password`,
    text,
    html,
  });

  if (error) {
    throw new Error(`Resend error: ${error.message}`);
  }
}

export async function sendTwoFactorCodeEmail(input: {
  toEmail: string;
  code: string;
  expiresInMinutes: number;
  purpose: "login" | "register" | "social";
}): Promise<void> {
  const resend = getResend();

  const subjectPrefix =
    input.purpose === "register"
      ? "Sign-up verification code"
      : input.purpose === "social"
        ? "Social sign-in verification code"
        : "Sign-in verification code";

  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;line-height:1.6;color:#111827;">
      <h2 style="margin-bottom:8px;">${APP_NAME} 2FA Verification</h2>
      <p>Use the code below to continue your authentication request:</p>
      <div style="font-size:30px;font-weight:700;letter-spacing:6px;padding:14px 18px;background:#f3f4f6;border-radius:10px;display:inline-block;">
        ${input.code}
      </div>
      <p style="margin-top:16px;">This code expires in ${input.expiresInMinutes} minutes.</p>
      <p style="color:#6b7280;">If you did not initiate this request, ignore this email.</p>
    </div>
  `;

  const text = [
    `${APP_NAME} 2FA Verification`,
    "",
    "Use this code to continue:",
    input.code,
    "",
    `Code expires in ${input.expiresInMinutes} minutes.`,
    "If you did not initiate this request, ignore this email.",
  ].join("\n");

  const { error } = await resend.emails.send({
    from: `${APP_NAME} <${FROM_EMAIL}>`,
    to: input.toEmail,
    subject: `${APP_NAME}: ${subjectPrefix}`,
    text,
    html,
  });

  if (error) {
    throw new Error(`Resend error: ${error.message}`);
  }
}
