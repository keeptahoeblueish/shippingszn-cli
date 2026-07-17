// Vendored from the shippingszn monorepo (lib/checklist-data/src/types.ts).
// Trimmed to the paid-free type aliases that public.ts depends on. The paid
// rich-content interfaces (CliPrompt, ChecklistItem, ReferenceLink) live
// server-side and are intentionally not part of the open-source CLI.

export type Priority = "critical" | "high" | "medium" | "lower";

export type Category =
  | "Security"
  | "Infrastructure"
  | "Operations"
  | "Product & Launch"
  | "Growth";

export type TimeEstimate = "5 min" | "15 min" | "30 min" | "1 hr" | "2 hr+";

/** Whether the public CLI scans for this item, or whether owner verification is required. */
export type CliCoverage = "automated" | "manual_only";
