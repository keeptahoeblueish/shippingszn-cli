import * as path from "node:path";
import { isTextFile, readFileSafe } from "../scan.js";
import type { Severity } from "../items.js";
import type { CheckContext, Finding } from "./types.js";
import {
  findLine,
  isScanExempt,
  lineContainsIgnoreMarker,
  relPosix,
} from "./helpers.js";

interface DangerousPattern {
  id: string;
  regex: RegExp;
  itemId: string;
  severity: Severity;
  message: string;
}

const DANGEROUS_PATTERNS: DangerousPattern[] = [
  {
    id: "dangerously-set-inner-html",
    regex: /dangerouslySetInnerHTML/,
    itemId: "common-attacks",
    severity: "high",
    message: "Use of dangerouslySetInnerHTML — make sure the content is sanitized or comes from a trusted source.",
  },
  {
    id: "eval-call",
    regex: /(^|[^A-Za-z0-9_$])eval\s*\(/,
    itemId: "common-attacks",
    severity: "high",
    message: "Use of eval() — almost always avoidable and a common path to remote code execution if any input is user-controlled.",
  },
  {
    id: "cors-wildcard",
    regex: /Access-Control-Allow-Origin\s*[:=]\s*['"`]\*['"`]/i,
    itemId: "common-attacks",
    severity: "medium",
    message: "Wildcard CORS (Access-Control-Allow-Origin: *). Lock this down to specific origins for any authenticated endpoint.",
  },
];

export async function checkDangerousPatterns(ctx: CheckContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    if (isScanExempt(file.relPath)) continue;
    const ext = path.extname(file.relPath).toLowerCase();
    if (![".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".html"].includes(ext)) continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    for (const pat of DANGEROUS_PATTERNS) {
      const m = pat.regex.exec(content);
      if (!m) continue;
      if (lineContainsIgnoreMarker(content, m.index)) continue;
      const line = findLine(content, m.index);
      findings.push({
        checkId: pat.id,
        itemId: pat.itemId,
        severity: pat.severity,
        message: pat.message,
        file: relPosix(file.relPath),
        line,
      });
    }
  }
  return findings;
}
