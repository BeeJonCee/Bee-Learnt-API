import { eq } from "drizzle-orm";
import { db } from "../core/database/index.js";
import { userPreferences, type DashboardLayoutItem, type WidgetSettings } from "../core/database/schema/index.js";

export interface UserPreferencesData {
  dashboardLayout: DashboardLayoutItem[] | null;
  widgetSettings: WidgetSettings | null;
  themeMode: string | null;
}

export async function getUserPreferences(userId: string): Promise<UserPreferencesData | null> {
  const result = await db
    .select()
    .from(userPreferences)
    .where(eq(userPreferences.userId, userId))
    .limit(1);

  if (result.length === 0) {
    return null;
  }

  const prefs = result[0];
  return {
    dashboardLayout: prefs.dashboardLayout ?? null,
    widgetSettings: prefs.widgetSettings ?? null,
    themeMode: prefs.themeMode ?? null,
  };
}

export async function updateUserPreferences(
  userId: string,
  updates: Partial<{
    dashboardLayout: DashboardLayoutItem[];
    widgetSettings: WidgetSettings;
    themeMode: string;
  }>
): Promise<UserPreferencesData> {
  // Check if preferences exist
  const existing = await db
    .select()
    .from(userPreferences)
    .where(eq(userPreferences.userId, userId))
    .limit(1);

  const updateData = {
    ...(updates.dashboardLayout !== undefined && { dashboardLayout: updates.dashboardLayout }),
    ...(updates.widgetSettings !== undefined && { widgetSettings: updates.widgetSettings }),
    ...(updates.themeMode !== undefined && { themeMode: updates.themeMode }),
    updatedAt: new Date(),
  };

  if (existing.length === 0) {
    // Create new preferences
    const [inserted] = await db
      .insert(userPreferences)
      .values({
        userId,
        dashboardLayout: updates.dashboardLayout ?? null,
        widgetSettings: updates.widgetSettings ?? null,
        themeMode: updates.themeMode ?? "dark",
      })
      .returning();

    return {
      dashboardLayout: inserted.dashboardLayout ?? null,
      widgetSettings: inserted.widgetSettings ?? null,
      themeMode: inserted.themeMode ?? null,
    };
  }

  // Update existing preferences
  const [updated] = await db
    .update(userPreferences)
    .set(updateData)
    .where(eq(userPreferences.userId, userId))
    .returning();

  return {
    dashboardLayout: updated.dashboardLayout ?? null,
    widgetSettings: updated.widgetSettings ?? null,
    themeMode: updated.themeMode ?? null,
  };
}

export async function deleteUserPreferences(userId: string): Promise<void> {
  await db.delete(userPreferences).where(eq(userPreferences.userId, userId));
}
