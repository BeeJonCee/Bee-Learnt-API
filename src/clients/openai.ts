import { env } from "../config/env.js";

let cachedClient: any = null;

export async function getOpenAiClient(): Promise<any> {
  if (cachedClient) {
    return cachedClient;
  }

  if (!env.openAiApiKey) {
    throw new Error("OPENAI_API_KEY is not set");
  }

  const { default: OpenAI } = await import("openai");
  cachedClient = new OpenAI({ apiKey: env.openAiApiKey });
  return cachedClient;
}
