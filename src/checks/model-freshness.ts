import * as path from "node:path";
import { isTextFile, readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";
import {
  findLine,
  isLikelyNonRuntimePath,
  isScanExempt,
  lineContainsIgnoreMarker,
  relPosix,
} from "./helpers.js";
import { makeFinding } from "./make-finding.js";

/**
 * Hardcoded AI model IDs rot. Providers retire dated snapshots on a schedule,
 * and a call to a retired ID returns an error at runtime — so an app that
 * pinned a model string silently breaks on the shutdown date. This check flags
 * model IDs used in code (model: "..." / MODEL = "...") that are already
 * retired, scheduled for shutdown, or pinned to a dated snapshot.
 *
 * The deprecation table below is a point-in-time snapshot (see dates) and needs
 * periodic refresh from the providers' official deprecation pages:
 *   OpenAI:    https://platform.openai.com/docs/deprecations
 *   Anthropic: https://docs.claude.com/en/docs/about-claude/model-deprecations
 *   Google:    https://ai.google.dev/gemini-api/docs/deprecations
 */
interface ModelDeprecation {
  id: string;
  status: "retired" | "scheduled";
  date: string;
  provider: string;
}

const MODEL_DEPRECATIONS: readonly ModelDeprecation[] = [
  // OpenAI — shutdown waves announced Apr 2026.
  {
    id: "gpt-5-chat-latest",
    status: "scheduled",
    date: "2026-07-23",
    provider: "OpenAI",
  },
  {
    id: "gpt-5-codex",
    status: "scheduled",
    date: "2026-07-23",
    provider: "OpenAI",
  },
  {
    id: "gpt-5.1-codex",
    status: "scheduled",
    date: "2026-07-23",
    provider: "OpenAI",
  },
  {
    id: "gpt-5.1-codex-max",
    status: "scheduled",
    date: "2026-07-23",
    provider: "OpenAI",
  },
  {
    id: "gpt-5.1-codex-mini",
    status: "scheduled",
    date: "2026-07-23",
    provider: "OpenAI",
  },
  {
    id: "o3-deep-research",
    status: "scheduled",
    date: "2026-07-23",
    provider: "OpenAI",
  },
  {
    id: "o4-mini-deep-research",
    status: "scheduled",
    date: "2026-07-23",
    provider: "OpenAI",
  },
  {
    id: "gpt-3.5-turbo-0125",
    status: "scheduled",
    date: "2026-10-23",
    provider: "OpenAI",
  },
  {
    id: "gpt-4-0613",
    status: "scheduled",
    date: "2026-10-23",
    provider: "OpenAI",
  },
  {
    id: "gpt-4-turbo",
    status: "scheduled",
    date: "2026-10-23",
    provider: "OpenAI",
  },
  {
    id: "gpt-4o-2024-05-13",
    status: "scheduled",
    date: "2026-10-23",
    provider: "OpenAI",
  },
  {
    id: "gpt-4.1-nano",
    status: "scheduled",
    date: "2026-10-23",
    provider: "OpenAI",
  },
  { id: "o1", status: "scheduled", date: "2026-10-23", provider: "OpenAI" },
  {
    id: "o3-mini",
    status: "scheduled",
    date: "2026-10-23",
    provider: "OpenAI",
  },
  {
    id: "o4-mini",
    status: "scheduled",
    date: "2026-10-23",
    provider: "OpenAI",
  },
  {
    id: "gpt-image-1",
    status: "scheduled",
    date: "2026-10-23",
    provider: "OpenAI",
  },
  {
    id: "chatgpt-4o-latest",
    status: "retired",
    date: "2026-02-17",
    provider: "OpenAI",
  },
  // Anthropic — Claude 3/4 retirements across 2026.
  {
    id: "claude-3-opus",
    status: "retired",
    date: "2026-01-05",
    provider: "Anthropic",
  },
  {
    id: "claude-3-haiku",
    status: "retired",
    date: "2026-04-20",
    provider: "Anthropic",
  },
  {
    id: "claude-sonnet-4",
    status: "retired",
    date: "2026-06-15",
    provider: "Anthropic",
  },
  {
    id: "claude-opus-4",
    status: "retired",
    date: "2026-06-15",
    provider: "Anthropic",
  },
  {
    id: "claude-opus-4-1",
    status: "scheduled",
    date: "2026-08-05",
    provider: "Anthropic",
  },
  // Google Gemini — 2.0 dead, 2.5 dated.
  {
    id: "gemini-2.0-flash",
    status: "retired",
    date: "2026-06-01",
    provider: "Google",
  },
  {
    id: "gemini-2.0-flash-001",
    status: "retired",
    date: "2026-06-01",
    provider: "Google",
  },
  {
    id: "gemini-2.0-flash-lite",
    status: "retired",
    date: "2026-06-01",
    provider: "Google",
  },
  {
    id: "gemini-2.0-flash-lite-001",
    status: "retired",
    date: "2026-06-01",
    provider: "Google",
  },
  {
    id: "gemini-2.5-pro",
    status: "scheduled",
    date: "2026-10-16",
    provider: "Google",
  },
  {
    id: "gemini-2.5-flash",
    status: "scheduled",
    date: "2026-10-16",
    provider: "Google",
  },
  {
    id: "gemini-2.5-flash-lite",
    status: "scheduled",
    date: "2026-10-16",
    provider: "Google",
  },
];

// Longest ids first so a dated variant matches before its base id.
const DEPRECATIONS_BY_LENGTH = [...MODEL_DEPRECATIONS].sort(
  (a, b) => b.id.length - a.id.length,
);

// A line that assigns/passes a model — the only context we flag, so prose that
// merely names a model (docs, changelogs, this very table) never triggers.
const MODEL_KEY =
  /\b(model|model_id|model_name|modelname|deployment|engine)\b\s*[:=]/i;

// A quoted string that looks like a provider model id.
const MODEL_LITERAL =
  /["'`]((?:gpt-|o[1-9]|claude-|gemini-|text-embedding-|dall-e|davinci|chatgpt-)[\w.\-]*)["'`]/gi;

// A dated snapshot suffix: -YYYY-MM-DD or a 4-digit date code like -0613 / -0125.
const DATED_SNAPSHOT = /-(?:20\d{2}-\d{2}-\d{2}|\d{4})$/;

const CODE_EXTS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".rb",
  ".go",
  ".java",
  ".kt",
  ".php",
  ".cs",
  ".rs",
  ".env",
]);

function classify(candidate: string): {
  status: "retired" | "scheduled" | "dated";
  hit?: ModelDeprecation;
} | null {
  const lower = candidate.toLowerCase();
  for (const dep of DEPRECATIONS_BY_LENGTH) {
    if (lower === dep.id) {
      return { status: dep.status, hit: dep };
    }
    // Only treat a longer id as the same model when the extra suffix is a
    // dated snapshot (e.g. "claude-3-opus" → "-2024-02-29", "gpt-4-turbo" →
    // "-0613"). A version successor like "claude-sonnet-4-5" / "claude-opus-4-8"
    // is a DIFFERENT, current model and must not inherit the base id's
    // retirement — a bare startsWith would falsely flag it as retired.
    if (lower.startsWith(`${dep.id}-`)) {
      const suffix = lower.slice(dep.id.length);
      if (DATED_SNAPSHOT.test(suffix)) {
        return { status: dep.status, hit: dep };
      }
    }
  }
  if (DATED_SNAPSHOT.test(lower)) return { status: "dated" };
  return null;
}

function safeLifecycleEvidence(
  verdict: NonNullable<ReturnType<typeof classify>>,
): string {
  if (verdict.hit) {
    return `Matched model-lifecycle category: ${verdict.status}; provider: ${verdict.hit.provider}; lifecycle date: ${verdict.hit.date}. The matched source line is intentionally omitted.`;
  }
  return "Matched model-lifecycle category: dated snapshot. The matched source line is intentionally omitted.";
}

export async function checkModelFreshness(
  ctx: CheckContext,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    if (isScanExempt(file.relPath)) continue;
    if (isLikelyNonRuntimePath(file.relPath)) continue;
    const ext = path.extname(file.relPath).toLowerCase();
    if (!CODE_EXTS.has(ext)) continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    if (!MODEL_KEY.test(content)) continue;

    let lineStart = 0;
    for (const rawLine of content.split("\n")) {
      const lineOffset = lineStart;
      lineStart += rawLine.length + 1;
      if (!MODEL_KEY.test(rawLine)) continue;
      MODEL_LITERAL.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = MODEL_LITERAL.exec(rawLine)) !== null) {
        const candidate = m[1] as string;
        const charIndex = lineOffset + m.index;
        if (lineContainsIgnoreMarker(content, charIndex)) continue;
        const verdict = classify(candidate);
        if (!verdict) continue;

        if (verdict.status === "retired" && verdict.hit) {
          findings.push(
            makeFinding({
              checkId: "model-freshness",
              itemId: "model-freshness",
              severity: "critical",
              message: `Model "${candidate}" was retired by ${verdict.hit.provider} on ${verdict.hit.date}. Calls to it now fail — this AI feature is broken.`,
              file: relPosix(file.relPath),
              line: findLine(content, charIndex),
              evidence: safeLifecycleEvidence(verdict),
            }),
          );
        } else if (verdict.status === "scheduled" && verdict.hit) {
          findings.push(
            makeFinding({
              checkId: "model-freshness",
              itemId: "model-freshness",
              severity: "high",
              message: `Model "${candidate}" is scheduled for shutdown by ${verdict.hit.provider} on ${verdict.hit.date}. It will start erroring on that date unless you migrate.`,
              file: relPosix(file.relPath),
              line: findLine(content, charIndex),
              evidence: safeLifecycleEvidence(verdict),
            }),
          );
        } else if (verdict.status === "dated") {
          findings.push(
            makeFinding({
              checkId: "model-freshness",
              itemId: "model-freshness",
              severity: "lower",
              message: `Model "${candidate}" is a pinned dated snapshot. Dated snapshots get retired on a schedule — drive the model from config/an alias, not a literal.`,
              file: relPosix(file.relPath),
              line: findLine(content, charIndex),
              evidence: safeLifecycleEvidence(verdict),
            }),
          );
        }
      }
    }
  }
  return findings.slice(0, 25);
}
