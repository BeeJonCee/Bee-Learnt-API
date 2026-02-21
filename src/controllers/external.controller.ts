import type { Request, Response } from "express";
import { env } from "../config/env.js";
import { asyncHandler } from "../core/middleware/async-handler.js";

const fallbackFeed = [
  {
    title: "Emerging AI tools for classrooms",
    source: "BeeLearnt Feed",
    url: "https://example.com/ai-classrooms",
    publishedAt: new Date().toISOString(),
  },
  {
    title: "STEM careers spotlight: data science",
    source: "BeeLearnt Feed",
    url: "https://example.com/stem-data-science",
    publishedAt: new Date().toISOString(),
  },
];

export const educationFeed = asyncHandler(async (_req: Request, res: Response) => {
  if (!env.newsApiKey) {
    res.json({ items: fallbackFeed, source: "fallback" });
    return;
  }

  const url = `https://newsapi.org/v2/everything?q=education%20technology&language=en&sortBy=publishedAt&pageSize=5&apiKey=${env.newsApiKey}`;

  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("News API unavailable");
    }
    const payload = (await response.json()) as any;
    const items = (payload.articles || []).map((article: any) => ({
      title: article.title,
      source: article.source?.name ?? "News",
      url: article.url,
      publishedAt: article.publishedAt,
    }));
    res.json({ items, source: "newsapi" });
  } catch {
    res.json({ items: fallbackFeed, source: "fallback" });
  }
});
