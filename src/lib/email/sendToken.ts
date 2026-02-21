/**
 * Email Service for Token Distribution
 * 
 * Sends daily module unlock tokens to administrators
 * who can then forward them to students.
 */

import * as nodemailer from "nodemailer";
import { env } from "../../config/env.js";

// ============ EMAIL CONFIGURATION ============

// Configure your email service here (Gmail, SendGrid, AWS SES, etc.)
const transporter = nodemailer.createTransport({
  host: env.smtpHost || "smtp.gmail.com",
  port: env.smtpPort || 587,
  secure: env.smtpSecure || false, // true for 465, false for other ports
  auth: {
    user: env.smtpUser || "",
    pass: env.smtpPassword || "",
  },
});

// Admin email address (from env or default)
const ADMIN_EMAIL = env.adminEmail || "admin@beelearnt.com";
const FROM_EMAIL = env.fromEmail || "noreply@beelearnt.com";
const APP_NAME = "BeeLearnt";
const APP_URL = env.appUrl || "http://localhost:3000";

function hasSmtpCredentials() {
  return Boolean(env.smtpUser?.trim() && env.smtpPassword?.trim());
}

// ============ EMAIL TEMPLATES ============

/**
 * HTML template for module unlock token email
 */
function getTokenEmailHtml(data: {
  moduleName: string;
  moduleId: number;
  token: string;
  studentName?: string;
  requestedBy: string;
  expiresAt: Date;
}): string {
  const expiryTime = data.expiresAt.toLocaleString("en-ZA", {
    dateStyle: "full",
    timeStyle: "short",
  });

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Module Unlock Token</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
          background-color: #f5f5f5;
        }
        .container {
          background-color: #ffffff;
          border-radius: 8px;
          padding: 30px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header {
          text-align: center;
          padding-bottom: 20px;
          border-bottom: 2px solid #f6c945;
        }
        .header h1 {
          color: #2c3e50;
          margin: 0 0 10px 0;
        }
        .token-box {
          background-color: #f8f9fa;
          border: 2px dashed #f6c945;
          border-radius: 8px;
          padding: 20px;
          text-align: center;
          margin: 25px 0;
        }
        .token {
          font-size: 32px;
          font-weight: bold;
          color: #f6c945;
          letter-spacing: 4px;
          font-family: 'Courier New', monospace;
          user-select: all;
        }
        .info-section {
          margin: 20px 0;
          padding: 15px;
          background-color: #f8f9fa;
          border-radius: 6px;
        }
        .info-label {
          font-weight: 600;
          color: #555;
          margin-bottom: 5px;
        }
        .info-value {
          color: #333;
        }
        .warning {
          background-color: #fff3cd;
          border-left: 4px solid #ffc107;
          padding: 12px;
          margin: 20px 0;
          border-radius: 4px;
        }
        .footer {
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #ddd;
          font-size: 12px;
          color: #777;
          text-align: center;
        }
        .button {
          display: inline-block;
          padding: 12px 24px;
          background-color: #f6c945;
          color: #000;
          text-decoration: none;
          border-radius: 6px;
          font-weight: 600;
          margin: 15px 0;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🔓 Module Unlock Token</h1>
          <p>${APP_NAME} Education Platform</p>
        </div>

        <div style="margin: 25px 0;">
          <p>A new module unlock token has been requested:</p>
        </div>

        <div class="token-box">
          <p style="margin: 0 0 10px 0; color: #666; font-size: 14px;">Today's Unlock Token</p>
          <div class="token">${data.token}</div>
          <p style="margin: 10px 0 0 0; color: #666; font-size: 12px;">Click to copy</p>
        </div>

        <div class="info-section">
          <div style="margin-bottom: 12px;">
            <div class="info-label">Module:</div>
            <div class="info-value">${data.moduleName} (ID: ${data.moduleId})</div>
          </div>
          ${
            data.studentName
              ? `
          <div style="margin-bottom: 12px;">
            <div class="info-label">Student:</div>
            <div class="info-value">${data.studentName}</div>
          </div>
          `
              : ""
          }
          <div style="margin-bottom: 12px;">
            <div class="info-label">Requested by:</div>
            <div class="info-value">${data.requestedBy}</div>
          </div>
          <div>
            <div class="info-label">Valid until:</div>
            <div class="info-value">${expiryTime}</div>
          </div>
        </div>

        <div class="warning">
          <strong>⚠️ Important:</strong>
          <ul style="margin: 10px 0 0 0; padding-left: 20px;">
            <li>This token is valid for today only</li>
            <li>Forward this token to the student securely</li>
            <li>Students have maximum 5 attempts to enter the correct token</li>
            <li>Do not share this token publicly</li>
          </ul>
        </div>

        <div style="text-align: center;">
          <a href="${APP_URL}/modules/${data.moduleId}" class="button">View Module</a>
        </div>

        <div class="footer">
          <p>This is an automated message from ${APP_NAME}</p>
          <p>If you did not request this token, please contact support immediately.</p>
        </div>
      </div>
    </body>
    </html>
  `;
}

/**
 * Plain text version of token email
 */
function getTokenEmailText(data: {
  moduleName: string;
  moduleId: number;
  token: string;
  studentName?: string;
  requestedBy: string;
  expiresAt: Date;
}): string {
  const expiryTime = data.expiresAt.toLocaleString();

  return `
${APP_NAME} - Module Unlock Token

A new module unlock token has been requested.

TODAY'S UNLOCK TOKEN: ${data.token}

MODULE: ${data.moduleName} (ID: ${data.moduleId})
${data.studentName ? `STUDENT: ${data.studentName}\n` : ""}REQUESTED BY: ${data.requestedBy}
VALID UNTIL: ${expiryTime}

IMPORTANT:
- This token is valid for today only
- Forward this token to the student securely
- Students have maximum 5 attempts to enter the correct token
- Do not share this token publicly

View Module: ${APP_URL}/modules/${data.moduleId}

---
This is an automated message from ${APP_NAME}
If you did not request this token, please contact support immediately.
  `;
}

// ============ EMAIL SENDING ============

/**
 * Send module unlock token to admin
 */
export async function sendTokenEmail(data: {
  moduleName: string;
  moduleId: number;
  token: string;
  studentName?: string;
  requestedBy: string;
  expiresAt: Date;
  adminEmail?: string; // Override default admin email
}): Promise<{ success: boolean; messageId?: string; error?: string }> {
  try {
    if (!hasSmtpCredentials()) {
      return {
        success: false,
        error: "SMTP credentials are not configured",
      };
    }

    const toEmail = data.adminEmail || ADMIN_EMAIL;

    if (!toEmail) {
      return {
        success: false,
        error: "Admin email not configured",
      };
    }

    const info = await transporter.sendMail({
      from: `"${APP_NAME}" <${FROM_EMAIL}>`,
      to: toEmail,
      subject: `🔓 Module Unlock Token: ${data.moduleName}`,
      text: getTokenEmailText(data),
      html: getTokenEmailHtml(data),
    });

    console.log("[sendTokenEmail] Email sent:", info.messageId);

    return {
      success: true,
      messageId: info.messageId,
    };
  } catch (error) {
    console.error("[sendTokenEmail] Failed to send email:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

/**
 * Send notification when student successfully unlocks module
 */
export async function sendUnlockSuccessEmail(data: {
  studentName: string;
  studentEmail: string;
  moduleName: string;
  moduleId: number;
  unlockedAt: Date;
}): Promise<{ success: boolean; messageId?: string; error?: string }> {
  try {
    if (!hasSmtpCredentials()) {
      return {
        success: false,
        error: "SMTP credentials are not configured",
      };
    }

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #f6c945; color: #000; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background-color: #f8f9fa; padding: 20px; border-radius: 0 0 8px 8px; }
          .button { display: inline-block; padding: 12px 24px; background-color: #f6c945; color: #000; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 15px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 Module Unlocked!</h1>
          </div>
          <div class="content">
            <p>Hi ${data.studentName},</p>
            <p>Great news! You have successfully unlocked:</p>
            <h2 style="color: #f6c945;">${data.moduleName}</h2>
            <p>You can now access all lessons, quizzes, and resources in this module.</p>
            <div style="text-align: center;">
              <a href="${APP_URL}/modules/${data.moduleId}" class="button">Start Learning</a>
            </div>
            <p style="margin-top: 20px;">Happy learning!</p>
            <p>- The ${APP_NAME} Team</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
Hi ${data.studentName},

Great news! You have successfully unlocked: ${data.moduleName}

You can now access all lessons, quizzes, and resources in this module.

Start Learning: ${APP_URL}/modules/${data.moduleId}

Happy learning!
- The ${APP_NAME} Team
    `;

    const info = await transporter.sendMail({
      from: `"${APP_NAME}" <${FROM_EMAIL}>`,
      to: data.studentEmail,
      subject: `🎉 Module Unlocked: ${data.moduleName}`,
      text,
      html,
    });

    return {
      success: true,
      messageId: info.messageId,
    };
  } catch (error) {
    console.error("[sendUnlockSuccessEmail] Failed:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

/**
 * Verify email configuration is working
 */
export async function verifyEmailConfig(): Promise<boolean> {
  try {
    if (!hasSmtpCredentials()) {
      console.warn("[Email] SMTP credentials are not configured");
      return false;
    }
    await transporter.verify();
    console.log("[Email] Configuration verified successfully");
    return true;
  } catch (error) {
    console.error("[Email] Configuration verification failed:", error);
    return false;
  }
}
