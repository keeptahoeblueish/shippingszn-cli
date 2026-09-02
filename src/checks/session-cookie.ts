import * as path from "node:path";
import { isTextFile, readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";
import {
  findLine,
  isLikelyNonRuntimePath,
  isScanExempt,
  isUiLibraryPrimitive,
  relPosix,
} from "./helpers.js";
import { makeFinding } from "./make-finding.js";

// Detects cookie-setting code with missing security flags. Conservative:
// only fires when we find an actual `res.cookie(`, `setCookie(`,
// or `cookie:` config block AND one of httpOnly / secure / sameSite is
// either absent or explicitly disabled. Each finding cites the exact
// line.
//
// Confidence: PROVES when a flag is explicitly missing (e.g., httpOnly
// not set in a cookie config). Owner-verify wording when ambiguous.

// Each pattern matches only up to and including the call's opening "(".
// The argument list is then extracted with balanced-paren scanning so a
// flag whose VALUE is itself a call (e.g. `secure: isProd()`) or whose
// options are a signed value (e.g. `sign(token)`) doesn't truncate the
// block at the first ")" and hide the real flags.
const COOKIE_SET_PATTERNS: ReadonlyArray<{ regex: RegExp; shape: string }> = [
  {
    regex: /\bres\.cookie\s*\(/m,
    shape: "Express res.cookie(...)",
  },
  {
    regex: /\bsetCookie\s*\(/m,
    shape: "setCookie(...) call",
  },
  {
    regex: /\bcookies\s*\(\s*\)\.set\s*\(/m,
    shape: "Next.js cookies().set(...)",
  },
];

// Given the index of a call's opening "(", return the substring up to its
// balanced ")". Naive depth counting is enough for cookie option objects;
// capped so a malformed/unterminated call can't run away.
function extractCallArgs(content: string, parenIdx: number): string {
  let depth = 0;
  const end = Math.min(content.length, parenIdx + 600);
  for (let i = parenIdx; i < end; i++) {
    const ch = content[i];
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return content.slice(parenIdx, i + 1);
    }
  }
  return content.slice(parenIdx, end);
}

// Session-config object form: matches `cookie: { ... }` blocks that
// often configure express-session / iron-session / next-auth.
const SESSION_CONFIG_REGEX = /\bcookie\s*:\s*\{[\s\S]{0,400}\}/g;

const RUNTIME_EXTS: ReadonlySet<string> = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
]);

function evaluateCookieBlock(block: string): {
  missing: string[];
  insecure: string[];
} {
  const missing: string[] = [];
  const insecure: string[] = [];

  if (!/httpOnly\s*[:=]/i.test(block)) {
    missing.push("httpOnly");
  } else if (/httpOnly\s*[:=]\s*(false|0)/i.test(block)) {
    insecure.push("httpOnly: false (JS-readable, exposed to XSS)");
  }

  if (!/secure\s*[:=]/i.test(block)) {
    missing.push("secure");
  } else if (/secure\s*[:=]\s*(false|0)/i.test(block)) {
    insecure.push("secure: false (will travel over plain HTTP)");
  }

  if (!/sameSite\s*[:=]/i.test(block)) {
    missing.push("sameSite");
  }

  return { missing, insecure };
}

export async function checkSessionCookie(
  ctx: CheckContext,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const seenFiles = new Set<string>();

  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    if (isScanExempt(file.relPath)) continue;
    if (isLikelyNonRuntimePath(file.relPath)) continue;
    if (isUiLibraryPrimitive(file.relPath)) continue;

    const ext = path.extname(file.relPath).toLowerCase();
    if (!RUNTIME_EXTS.has(ext)) continue;

    const content = await readFileSafe(file);
    if (!content) continue;

    const rel = relPosix(file.relPath);
    if (seenFiles.has(rel)) continue;

    // Pass 1: session-config blocks (cookie: { ... })
    let match: RegExpExecArray | null;
    SESSION_CONFIG_REGEX.lastIndex = 0;
    while ((match = SESSION_CONFIG_REGEX.exec(content)) !== null) {
      const { missing, insecure } = evaluateCookieBlock(match[0]);
      if (missing.length === 0 && insecure.length === 0) continue;

      const line = findLine(content, match.index);
      const reasons: string[] = [];
      if (missing.length > 0) {
        reasons.push(`missing flag(s): ${missing.join(", ")}`);
      }
      if (insecure.length > 0) {
        reasons.push(`insecure setting(s): ${insecure.join("; ")}`);
      }

      findings.push(
        makeFinding({
          checkId: "session-cookie-flags-missing",
          itemId: "session-management",
          severity: insecure.length > 0 ? "high" : "medium",
          message: `Session cookie config at ${rel}:${line} has ${reasons.join(" and ")}. Without httpOnly + secure + sameSite, session state is exposed to XSS, plain-HTTP transit, or cross-site request abuse. Owner must verify other config blocks aren't compensating.`,
          file: rel,
          line,
          evidence: `Cookie config block at ${rel}:${line}. ${reasons.join(". ")}.`,
        }),
      );
      seenFiles.add(rel);
      break;
    }
    if (seenFiles.has(rel)) continue;

    // Pass 2: res.cookie(...) and similar calls
    for (const { regex, shape } of COOKIE_SET_PATTERNS) {
      const m = regex.exec(content);
      if (!m) continue;
      // m[0] ends with the call's opening "(" — extract the balanced args.
      const parenIdx = m.index + m[0].length - 1;
      const block = extractCallArgs(content, parenIdx);
      const { missing, insecure } = evaluateCookieBlock(block);
      if (missing.length === 0 && insecure.length === 0) continue;

      const line = findLine(content, m.index);
      const reasons: string[] = [];
      if (missing.length > 0) {
        reasons.push(`missing flag(s): ${missing.join(", ")}`);
      }
      if (insecure.length > 0) {
        reasons.push(`insecure setting(s): ${insecure.join("; ")}`);
      }

      findings.push(
        makeFinding({
          checkId: "session-cookie-flags-missing",
          itemId: "session-management",
          severity: insecure.length > 0 ? "high" : "medium",
          message: `${shape} at ${rel}:${line} has ${reasons.join(" and ")}. Owner must verify the cookie isn't session-critical or that flags are set in a wrapping framework default.`,
          file: rel,
          line,
          evidence: `${shape} at ${rel}:${line}. ${reasons.join(". ")}.`,
        }),
      );
      seenFiles.add(rel);
      break;
    }
  }

  return findings;
}
