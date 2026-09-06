import type { ChecklistItem } from "./types.js";
import { ITEMS_CRITICAL } from "./items-critical.js";
import { ITEMS_HIGH } from "./items-high.js";
import { ITEMS_MEDIUM } from "./items-medium.js";
import { ITEMS_LOWER } from "./items-lower.js";

export * from "./types.js";
export * from "./metadata.js";

/**
 * The full launch checklist, assembled in display order: critical → high →
 * medium → lower. Items are immutable at runtime; mutate by editing the
 * per-priority modules in this directory.
 *
 * `number` is assigned here from the assembled position, so adding or
 * reordering items in the per-priority modules never requires hand-renumbering
 * every downstream item — the per-item `number` literal is a placeholder the
 * assembly overrides.
 */
export const CHECKLIST: ChecklistItem[] = [
  ...ITEMS_CRITICAL,
  ...ITEMS_HIGH,
  ...ITEMS_MEDIUM,
  ...ITEMS_LOWER,
].map((item, index) => ({ ...item, number: index + 1 }));

/** Lookup map keyed by item id for O(1) access. */
export const CHECKLIST_BY_ID: Record<string, ChecklistItem> =
  Object.fromEntries(CHECKLIST.map((item) => [item.id, item]));
