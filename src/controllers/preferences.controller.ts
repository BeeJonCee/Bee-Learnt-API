import type { Request, Response } from "express";
import {
  getUserPreferences,
  updateUserPreferences,
} from "../services/preferences.service.js";

export async function getPreferences(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const preferences = await getUserPreferences(userId);

    if (!preferences) {
      // Return empty preferences instead of 404
      res.json({
        dashboardLayout: null,
        widgetSettings: null,
        themeMode: "dark",
      });
      return;
    }

    res.json(preferences);
  } catch (error) {
    console.error("[getPreferences] Error:", error);
    res.status(500).json({ message: "Failed to get preferences" });
  }
}

export async function patchPreferences(req: Request, res: Response) {
  try {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const { dashboardLayout, widgetSettings, themeMode } = req.body;

    // Validate input
    if (dashboardLayout !== undefined && !Array.isArray(dashboardLayout)) {
      res.status(400).json({ message: "dashboardLayout must be an array" });
      return;
    }

    if (widgetSettings !== undefined && typeof widgetSettings !== "object") {
      res.status(400).json({ message: "widgetSettings must be an object" });
      return;
    }

    if (themeMode !== undefined && !["dark", "light", "system"].includes(themeMode)) {
      res.status(400).json({ message: "themeMode must be 'dark', 'light', or 'system'" });
      return;
    }

    const updated = await updateUserPreferences(userId, {
      dashboardLayout,
      widgetSettings,
      themeMode,
    });

    res.json(updated);
  } catch (error) {
    console.error("[patchPreferences] Error:", error);
    res.status(500).json({ message: "Failed to update preferences" });
  }
}
