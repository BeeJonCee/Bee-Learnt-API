import type { Request, Response } from "express";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { getOpenAiClient } from "../clients/openai.js";
import { rateLimit } from "../shared/utils/rate-limit.js";

const systemPrompt =
  "You are BeeLearnt, a helpful CAPS-aligned tutor for South African students. " +
  "Give clear, step-by-step explanations, short summaries, and optional practice questions. " +
  "Keep answers concise and age-appropriate.";

export const tutor = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id ?? null;
  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const limiter = rateLimit(`ai-tutor:${userId}`, { windowMs: 60_000, max: 10 });
  if (!limiter.allowed) {
    res.status(429).json({ message: "Rate limit exceeded" });
    return;
  }

  const client = await getOpenAiClient();
  const completion = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "system", content: systemPrompt }, ...req.body.messages],
  });

  const content = completion.choices[0]?.message?.content ?? "";
  res.json({ message: content });
});
