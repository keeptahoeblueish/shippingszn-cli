import type { ChecklistItem } from "./types.js";
import { ITEMS_CRITICAL_A } from "./items-critical-a.js";
import { ITEMS_CRITICAL_B } from "./items-critical-b.js";

export const ITEMS_CRITICAL: ChecklistItem[] = [
  ...ITEMS_CRITICAL_A,
  ...ITEMS_CRITICAL_B,
];
