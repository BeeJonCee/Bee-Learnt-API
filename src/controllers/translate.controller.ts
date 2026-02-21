import type { Request, Response } from "express";
import { z } from "zod";
import { asyncHandler } from "../core/middleware/async-handler.js";
import { getOpenAiClient } from "../clients/openai.js";
import { env } from "../config/env.js";

const translateSchema = z.object({
  text: z.string().min(1),
  targetLanguage: z.string().min(2),
});

export const translateText = asyncHandler(async (req: Request, res: Response) => {
  const parsed = translateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ message: "Invalid payload", issues: parsed.error.issues });
    return;
  }

  if (!env.openAiApiKey) {
    res.json({ translatedText: parsed.data.text, source: "fallback" });
    return;
  }

  const client = await getOpenAiClient();
  const completion = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "system",
        content:
          "You translate educational content clearly and preserve formatting. Return only the translated text.",
      },
      {
        role: "user",
        content: `Translate into ${parsed.data.targetLanguage}:\n\n${parsed.data.text}`,
      },
    ],
    temperature: 0.2,
  });

  const translatedText = completion.choices[0]?.message?.content?.trim() ?? parsed.data.text;
  res.json({ translatedText, source: "openai" });
});
