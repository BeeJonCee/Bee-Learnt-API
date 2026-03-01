import { env } from "../../config/env.js";
import { sendLoginAlertEmail } from "../../shared/email/send-two-factor.js";
import { logAudit } from "../../shared/audit/audit-log.js";
import { sendLoginAlertSmsViaNovu } from "../../shared/utils/novu.js";

export type LoginAlertMeta = {
  ipAddress: string | null;
  userAgent: string | null;
};

function parseBrowser(userAgent: string | null): string {
  if (!userAgent) return "Unknown browser";
  if (userAgent.includes("Edg/")) return "Microsoft Edge";
  if (userAgent.includes("Chrome/")) return "Google Chrome";
  if (userAgent.includes("Firefox/")) return "Mozilla Firefox";
  if (userAgent.includes("Safari/") && !userAgent.includes("Chrome/")) {
    return "Safari";
  }
  return "Unknown browser";
}

function parseDevice(userAgent: string | null): string {
  if (!userAgent) return "Unknown device";
  if (/mobile/i.test(userAgent)) return `${parseBrowser(userAgent)} (mobile)`;
  return `${parseBrowser(userAgent)} (desktop)`;
}

function inferLocation(ipAddress: string | null): string {
  if (!ipAddress) return "Unknown location";
  if (
    ipAddress === "127.0.0.1" ||
    ipAddress === "::1" ||
    ipAddress.startsWith("::ffff:127.0.0.1")
  ) {
    return "Localhost";
  }
  return ipAddress;
}

export async function sendLoginAlerts(input: {
  userId: string;
  email: string;
  phone: string | null;
  loginEmailAlertEnabled: boolean;
  loginSmsAlertEnabled: boolean;
  meta: LoginAlertMeta;
}): Promise<{ email: boolean; sms: boolean }> {
  if (!env.authEnableLoginAlerts) {
    return { email: false, sms: false };
  }

  const loginAtIso = new Date().toISOString();
  const device = parseDevice(input.meta.userAgent);
  const location = inferLocation(input.meta.ipAddress);

  let emailSent = false;
  let smsSent = false;

  if (input.loginEmailAlertEnabled) {
    try {
      await sendLoginAlertEmail({
        toEmail: input.email,
        loginAtIso,
        device,
        location,
      });
      emailSent = true;
    } catch (error) {
      console.warn("[auth-alerts] failed to send login email alert", {
        userId: input.userId,
        message: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  if (input.loginSmsAlertEnabled && input.phone) {
    try {
      const result = await sendLoginAlertSmsViaNovu({
        subscriberId: input.userId,
        phone: input.phone,
        loginAtIso,
        device,
        location,
      });

      if (!result.sent) {
        console.warn("[auth-alerts] failed to send login SMS alert", {
          userId: input.userId,
          reason: result.reason,
        });
      } else {
        smsSent = true;
      }
    } catch (error) {
      console.warn("[auth-alerts] failed to send login SMS alert", {
        userId: input.userId,
        message: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  await logAudit({
    actorId: input.userId,
    action: "login_alert_sent",
    entity: "user",
    details: {
      emailSent,
      smsSent,
      device,
      location,
      loginAtIso,
    },
  });

  return { email: emailSent, sms: smsSent };
}
