import * as path from "node:path";
import { isTextFile, readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";
import { relPosix } from "./helpers.js";
import { makeFinding } from "./make-finding.js";

// Detects vibe-coded apps shipping without /terms or /privacy routes.
// Legal pages are a baseline for any product that takes payment,
// collects email, or runs in the EU. Vibe-builders rarely scaffold
// these by default. The check looks for either a route file or a
// link in source — generous to avoid false positives.

const LEGAL_FILE_PATTERNS: ReadonlyArray<{
  regex: RegExp;
  itemKind: "terms" | "privacy";
}> = [
  { regex: /\/(terms|tos|terms-of-service)(\.[a-z]+)?(\/|$)/i, itemKind: "terms" },
  { regex: /\/privacy(-policy)?(\.[a-z]+)?(\/|$)/i, itemKind: "privacy" },
];

const LEGAL_LINK_PATTERNS: ReadonlyArray<{ regex: RegExp; itemKind: "terms" | "privacy" }> = [
  { regex: /href=["']\/(terms|tos|terms-of-service)\b/i, itemKind: "terms" },
  { regex: /href=["']\/privacy(-policy)?\b/i, itemKind: "privacy" },
  { regex: /to=["']\/(terms|tos)\b/i, itemKind: "terms" },
  { regex: /to=["']\/privacy\b/i, itemKind: "privacy" },
];

const RUNTIME_EXTS: ReadonlySet<string> = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".html",
  ".astro",
  ".svelte",
  ".vue",
]);

export async function checkLegalPages(
  ctx: CheckContext,
): Promise<Finding[]> {
  // Sanity gate: only flag if the project looks like a real app
  // (package.json present). Otherwise the check is too noisy on
  // doc repos, scripts, etc.
  const hasPkg = ctx.files.some(
    (f) => relPosix(f.relPath) === "package.json",
  );
  if (!hasPkg) return [];

  const found = new Set<"terms" | "privacy">();

  for (const file of ctx.files) {
    const rel = relPosix(file.relPath).toLowerCase();
    for (const { regex, itemKind } of LEGAL_FILE_PATTERNS) {
      if (regex.test(rel)) found.add(itemKind);
    }
    if (found.size === 2) break;
  }

  if (found.size < 2) {
    for (const file of ctx.files) {
      if (found.size === 2) break;
      if (!isTextFile(file)) continue;
      const ext = path.extname(file.relPath).toLowerCase();
      if (!RUNTIME_EXTS.has(ext)) continue;
      const content = await readFileSafe(file);
      if (!content) continue;
      for (const { regex, itemKind } of LEGAL_LINK_PATTERNS) {
        if (regex.test(content)) found.add(itemKind);
      }
    }
  }

  const findings: Finding[] = [];
  if (!found.has("terms")) {
    findings.push(
      makeFinding({
        checkId: "legal-page-terms-missing",
        itemId: "legal-pages",
        severity: "medium",
        message:
          "No Terms of Service route or link detected. If you take payment, run a marketplace, or collect user data, terms are a baseline expectation.",
        evidence:
          "No /terms, /tos, or /terms-of-service route file was found, and no source file linked to one.",
      }),
    );
  }
  if (!found.has("privacy")) {
    findings.push(
      makeFinding({
        checkId: "legal-page-privacy-missing",
        itemId: "legal-pages",
        severity: "medium",
        message:
          "No Privacy Policy route or link detected. EU GDPR, US state laws, and most app store / payment processor policies require a published privacy notice.",
        evidence:
          "No /privacy or /privacy-policy route file was found, and no source file linked to one.",
      }),
    );
  }
  return findings;
}
