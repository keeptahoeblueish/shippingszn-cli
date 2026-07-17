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

// Catches paid-AI calls without a rate-limit / spend-cap signal nearby.
// This is the headline finding the home page promises ("uncapped paid
// AI endpoints"). We grep for paid-AI hosts (and SDK constructors) and
// flag if no mitigation is within proximity.

const PAID_AI_HOSTS: ReadonlyArray<{ host: string; provider: string }> = [
  { host: "api.openai.com", provider: "OpenAI" },
  { host: "api.anthropic.com", provider: "Anthropic" },
  { host: "api.replicate.com", provider: "Replicate" },
  { host: "api.stability.ai", provider: "Stability AI" },
  { host: "api.mistral.ai", provider: "Mistral" },
  { host: "generativelanguage.googleapis.com", provider: "Google Gemini" },
  { host: "api.cohere.ai", provider: "Cohere" },
  { host: "api.cohere.com", provider: "Cohere" },
  { host: "api.together.xyz", provider: "Together AI" },
  { host: "openrouter.ai", provider: "OpenRouter" },
  { host: "api.groq.com", provider: "Groq" },
  { host: "api.fireworks.ai", provider: "Fireworks" },
];

const PAID_AI_SDK_PATTERNS: ReadonlyArray<{ regex: RegExp; provider: string }> =
  [
    { regex: /\bnew\s+OpenAI\s*\(/, provider: "OpenAI" },
    { regex: /\bnew\s+Anthropic\s*\(/, provider: "Anthropic" },
    { regex: /\b@anthropic-ai\/sdk\b/, provider: "Anthropic" },
    { regex: /\bfrom\s+["']openai["']/, provider: "OpenAI" },
    { regex: /\bfrom\s+["']@anthropic-ai\/sdk["']/, provider: "Anthropic" },
    { regex: /\bnew\s+Replicate\s*\(/, provider: "Replicate" },
    { regex: /\b@google\/generative-ai\b/, provider: "Google Gemini" },
    { regex: /\bnew\s+CohereClient\s*\(/, provider: "Cohere" },
  ];

const MITIGATION_REGEX =
  /\b(rateLimit|spendCap|rate-limit|spend-cap|rate_limit|spend_cap|express-rate-limit|@upstash\/ratelimit|@vercel\/edge|fastify-rate-limit|hono\/ratelimit|throttle|throttler|maxRequests|maxRequestsPerMinute|tokensPerMinute|tokensPerSecond|requestsPerMinute|requestsPerSecond|RateLimiter|Bottleneck|p-limit|p-throttle|limiter\(|ratelimit\(|withRateLimit|guard\b|budget\b|usageCap|maxTokens|max_tokens|maxOutputTokens|max_output_tokens|maxCompletionTokens|max_completion_tokens)\b/i;

const RUNTIME_EXTS: ReadonlySet<string> = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".rb",
  ".go",
  ".php",
]);

function hasMitigationNearby(content: string, hitIndex: number): boolean {
  const start = Math.max(0, hitIndex - 600);
  const end = Math.min(content.length, hitIndex + 600);
  return MITIGATION_REGEX.test(content.slice(start, end));
}

export async function checkApiSpendCap(ctx: CheckContext): Promise<Finding[]> {
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

    let hitIndex = -1;
    let providerLabel = "";
    let detectionShape: "host" | "sdk" = "host";

    for (const { host, provider } of PAID_AI_HOSTS) {
      const idx = content.indexOf(host);
      if (idx === -1) continue;
      hitIndex = idx;
      providerLabel = provider;
      break;
    }

    if (hitIndex === -1) {
      for (const { regex, provider } of PAID_AI_SDK_PATTERNS) {
        const m = regex.exec(content);
        if (!m) continue;
        hitIndex = m.index;
        providerLabel = provider;
        detectionShape = "sdk";
        break;
      }
    }

    if (hitIndex === -1) continue;
    if (hasMitigationNearby(content, hitIndex)) continue;

    const rel = relPosix(file.relPath);
    if (seenFiles.has(rel)) continue;
    seenFiles.add(rel);

    const line = findLine(content, hitIndex);
    const detectionDescriptor =
      detectionShape === "host"
        ? `Direct call to ${providerLabel} (paid API host)`
        : `${providerLabel} SDK in use`;

    findings.push(
      makeFinding({
        checkId: "api-spend-cap-missing",
        itemId: "api-spend-cap",
        severity: "high",
        message: `${detectionDescriptor} without a visible rate-limit, spend-cap, or throttle signal nearby. An attacker (or a runaway loop) can burn paid credits faster than your billing alerts fire.`,
        file: rel,
        line,
        evidence: `${detectionDescriptor} at ${rel}:${line}. No rate-limit / spend-cap signal within +/- 600 chars.`,
      }),
    );
  }

  return findings;
}
