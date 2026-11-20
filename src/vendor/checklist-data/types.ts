export type Priority = "critical" | "high" | "medium" | "lower";

export type Category =
  | "Security"
  | "Infrastructure"
  | "Operations"
  | "Product & Launch"
  | "Growth";

export type TimeEstimate = "5 min" | "15 min" | "30 min" | "1 hr" | "2 hr+";

export interface ReferenceLink {
  label: string;
  url: string;
}

/** Whether the public CLI scans for this item, or whether owner verification is required. */
export type CliCoverage = "automated" | "manual_only";

/**
 * Hand-curated rich-field content surfaced in the paid $49 launch report and
 * available to consumers (CLI / internal-audit) that don't strip them.
 */
export interface CliPrompt {
  /** 2-3 sentences explaining what specifically went wrong, in the user's voice. */
  whatFailed: string;
  /** 2-3 sentences on real-world consequences if shipped this way. */
  whyItBlocksLaunch: string;
  /** 2-4 sentences with specific, copy-pasteable fix actions. */
  fixInstructions: string;
  /** Paste-ready prompt for Cursor / Claude / Lovable that explains exactly what to change. */
  aiBuilderPrompt: string;
  /** 1-2 sentences: how to confirm the fix worked (specific shell command or browser action). */
  verificationStep: string;
}

export interface ChecklistItem {
  id: string;
  number: number;
  title: string;
  category: Category;
  priority: Priority;
  timeEstimate: TimeEstimate;
  what: string;
  why: string;
  steps: string[];
  redFlags: string[];
  prompt: string;
  references?: ReferenceLink[];

  /**
   * REQUIRED. Whether the public CLI scans for this item ("automated") or
   * owner verification is needed ("manual_only").
   */
  cliCoverage: CliCoverage;

  /**
   * Optional hand-curated item-specific rich-field content that flows into
   * automated findings when available.
   */
  cliPrompt?: CliPrompt;

  /**
   * REQUIRED when cliCoverage === "manual_only". One-sentence explanation of
   * why the scanner cannot prove this from static signals.
   */
  whyManual?: string;
}
