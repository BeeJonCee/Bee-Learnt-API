import type { Request, Response } from "express";
import { asyncHandler } from "../../core/middleware/async-handler.js";
import { getOpenAiClient } from "../../clients/openai.js";

export const translateText = asyncHandler(async (req: Request, res: Response) => {
  const { text, targetLanguage, sourceLanguage } = req.body as {
    text: string;
    targetLanguage: string;
    sourceLanguage?: string;
  };

  if (!text || typeof text !== "string" || text.trim().length === 0) {
    res.status(400).json({ message: "text is required" });
    return;
  }
  if (!targetLanguage || typeof targetLanguage !== "string") {
    res.status(400).json({ message: "targetLanguage is required" });
    return;
  }

  const openai = await getOpenAiClient();
  if (!openai) {
    res.status(503).json({ message: "Translation service is not configured" });
    return;
  }

  const systemPrompt = sourceLanguage
    ? `You are a professional translator. Translate from ${sourceLanguage} to ${targetLanguage}. Return only the translated text, no explanations.`
    : `You are a professional translator. Translate to ${targetLanguage}. Return only the translated text, no explanations.`;

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: text },
    ],
    temperature: 0.3,
    max_tokens: 2000,
  });

  const translated = completion.choices[0]?.message?.content?.trim() ?? "";

  res.json({
    original: text,
    translated,
    targetLanguage,
    sourceLanguage: sourceLanguage ?? "auto",
  });
});
