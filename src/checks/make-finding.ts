import type { Severity } from "../items.js";
import type { Finding } from "./types.js";

export interface MakeFindingInput {
  checkId: string;
  itemId: string;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
  evidence?: string;
}

/**
 * Build a diagnosis-only Finding. The paid remediation content (the curated
 * cliPrompt fields) is NOT attached here — it lives server-side and is enriched
 * from @workspace/checklist-data at serve time for authorized viewers, so the
 * open-source CLI neither bundles nor uploads it.
 */
export function makeFinding(input: MakeFindingInput): Finding {
  const out: Finding = {
    checkId: input.checkId,
    itemId: input.itemId,
    severity: input.severity,
    message: input.message,
  };

  if (input.file) out.file = input.file;
  if (input.line) out.line = input.line;
  if (input.evidence) out.evidence = input.evidence;

  return out;
}
