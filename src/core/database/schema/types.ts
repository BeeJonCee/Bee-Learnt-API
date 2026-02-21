/**
 * TypeScript interfaces for JSONB columns in the database schema
 */

// ── Dashboard & Preferences ─────────────────
export interface DashboardLayoutItem {
  i: string; // widget id
  x: number;
  y: number;
  w: number;
  h: number;
  minW?: number;
  minH?: number;
  static?: boolean;
}

export interface WidgetSettings {
  [widgetId: string]: {
    visible: boolean;
    collapsed?: boolean;
    config?: Record<string, unknown>;
  };
}

// ── Grading & Rubric ────────────────────────
export interface RubricCriterion {
  name: string;
  description: string;
  maxScore: number;
  levels: { score: number; descriptor: string }[];
}
