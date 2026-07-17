import * as path from "node:path";
import { isTextFile, readFileSafe } from "../scan.js";
import type { Severity } from "../items.js";
import type { CheckContext, Finding } from "./types.js";
import {
  findLine,
  isLikelyNonRuntimePath,
  isScanExempt,
  isUiLibraryPrimitive,
  lineContainsIgnoreMarker,
  relPosix,
} from "./helpers.js";
import { makeFinding } from "./make-finding.js";

interface DangerousPattern {
  id: string;
  regex: RegExp;
  itemId: string;
  severity: Severity;
  message: string;
  // Per-match exemption. Returns true when THIS specific match should be
  // skipped (evaluated per occurrence so a safe first hit can't mask a later
  // unsafe one).
  isSafeMatch?: (
    content: string,
    matchIndex: number,
    match: RegExpExecArray,
  ) => boolean;
}

// A reference to Node's child_process module anywhere in the file. Used to
// decide whether a member `.exec(` is a shell call (cp.exec) rather than
// RegExp.prototype.exec / String matching.
const CHILD_PROCESS_REF = /child_process/;

// Is the token at matchIndex a member call (`recv.exec(`) rather than a bare
// call (`exec(`)? Looks at the immediately preceding non-space char.
function isMemberCall(content: string, matchIndex: number): boolean {
  return /\.\s*$/.test(content.slice(Math.max(0, matchIndex - 40), matchIndex));
}

const DANGEROUS_PATTERNS: DangerousPattern[] = [
  {
    id: "dangerously-set-inner-html",
    regex: /dangerouslySetInnerHTML/g,
    itemId: "common-attacks",
    severity: "high",
    message:
      "Use of dangerouslySetInnerHTML — make sure the content is sanitized or comes from a trusted source.",
    isSafeMatch: (content, matchIndex) =>
      hasSafeDangerousHtmlContext(content, matchIndex),
  },
  {
    id: "eval-call",
    regex: /(^|[^A-Za-z0-9_$])eval\s*\(/g,
    itemId: "common-attacks",
    severity: "high",
    message:
      "Use of eval() — almost always avoidable and a common path to remote code execution if any input is user-controlled.",
  },
  {
    id: "cors-wildcard",
    regex: /Access-Control-Allow-Origin\s*[:=]\s*['"`]\*['"`]/gi,
    itemId: "common-attacks",
    severity: "medium",
    message:
      "Wildcard CORS (Access-Control-Allow-Origin: *). Lock this down to specific origins for any authenticated endpoint.",
  },
  {
    // Matches bare AND member forms (child_process.exec, cp.execSync,
    // require('child_process').execSync). RegExp/String .exec() false
    // positives are filtered in isSafeMatch below.
    id: "shell-exec-call",
    regex: /\b(exec|execSync)\s*\(/g,
    itemId: "common-attacks",
    severity: "high",
    message:
      "Shell execution via exec/execSync — if any argument includes user input, this is a command-injection path. Prefer execFile with an argument array, or validate input strictly against an allowlist.",
    isSafeMatch: (content, matchIndex, match) => {
      // execSync is never a RegExp/String method — always a shell call.
      if (match[1] === "execSync") return false;
      // A bare exec( is a destructured child_process import — flag it.
      if (!isMemberCall(content, matchIndex)) return false;
      // A member .exec( is a shell call only when child_process is imported;
      // otherwise it's almost certainly RegExp.prototype.exec / String work.
      return !CHILD_PROCESS_REF.test(content);
    },
  },
];

function hasSafeDangerousHtmlContext(content: string, index: number): boolean {
  const before = content.slice(Math.max(0, index - 1200), index);
  const after = content.slice(index, Math.min(content.length, index + 500));
  if (/\b(DOMPurify|sanitizeHtml|sanitize)\b/.test(before + after)) {
    return true;
  }
  return /<style[\s\S]{0,240}$/.test(before);
}

export async function checkDangerousPatterns(
  ctx: CheckContext,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    if (isScanExempt(file.relPath)) continue;
    if (isLikelyNonRuntimePath(file.relPath)) continue;
    if (isUiLibraryPrimitive(file.relPath)) continue;
    const ext = path.extname(file.relPath).toLowerCase();
    if (
      ![
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".json",
        ".html",
      ].includes(ext)
    )
      continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    for (const pat of DANGEROUS_PATTERNS) {
      // Evaluate ALL matches (global regex + loop) so a sanitized/ignored
      // first hit can't mask a later dangerous one. Emit at most one finding
      // per pattern per file — the first match that clears the exemptions.
      pat.regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = pat.regex.exec(content)) !== null) {
        if (m[0].length === 0) {
          pat.regex.lastIndex++;
          continue;
        }
        if (lineContainsIgnoreMarker(content, m.index)) continue;
        if (pat.isSafeMatch && pat.isSafeMatch(content, m.index, m)) continue;
        const line = findLine(content, m.index);
        findings.push(
          makeFinding({
            checkId: pat.id,
            itemId: pat.itemId,
            severity: pat.severity,
            message: pat.message,
            file: relPosix(file.relPath),
            line,
          }),
        );
        break;
      }
    }
  }
  return findings;
}
