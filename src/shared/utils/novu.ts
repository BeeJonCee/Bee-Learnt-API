import { env } from "../../config/env.js";

type NovuResult = {
  sent: boolean;
  reason?: string;
};

async function triggerNovuWorkflow(input: {
  workflowId: string;
  subscriberId: string;
  email?: string;
  phone?: string;
  payload: Record<string, unknown>;
}): Promise<NovuResult> {
  if (!env.novuApiKey) {
    return { sent: false, reason: "NOVU_API_KEY is not configured" };
  }

  if (!input.workflowId) {
    return { sent: false, reason: "Novu workflow ID is not configured" };
  }

  const response = await fetch(`${env.novuApiBaseUrl}/v1/events/trigger`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `ApiKey ${env.novuApiKey}`,
    },
    body: JSON.stringify({
      name: input.workflowId,
      to: {
        subscriberId: input.subscriberId,
        ...(input.email ? { email: input.email } : {}),
        ...(input.phone ? { phone: input.phone } : {}),
      },
      payload: input.payload,
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    return {
      sent: false,
      reason: `Novu request failed (${response.status}): ${body || "unknown"}`,
    };
  }

  return { sent: true };
}

export async function sendOtpSmsViaNovu(input: {
  subscriberId: string;
  phone: string;
  code: string;
  expiresInMinutes: number;
}): Promise<NovuResult> {
  return triggerNovuWorkflow({
    workflowId: env.novuWorkflowIdOtp,
    subscriberId: input.subscriberId,
    phone: input.phone,
    payload: {
      code: input.code,
      expiresInMinutes: input.expiresInMinutes,
      appName: "BeeLearnt",
    },
  });
}

export async function sendLoginAlertSmsViaNovu(input: {
  subscriberId: string;
  phone: string;
  loginAtIso: string;
  device: string;
  location: string;
}): Promise<NovuResult> {
  return triggerNovuWorkflow({
    workflowId: env.novuWorkflowIdLoginAlert,
    subscriberId: input.subscriberId,
    phone: input.phone,
    payload: {
      loginAtIso: input.loginAtIso,
      device: input.device,
      location: input.location,
      appName: "BeeLearnt",
    },
  });
}
