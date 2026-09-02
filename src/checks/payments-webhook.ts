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

// Detects projects with stripe in deps + a webhook-shaped route handler
// AND no signature-verification call in proximity. This is a real launch
// blocker on Stripe-using apps: forged webhooks can grant entitlements
// or trigger fulfillment.
//
// Confidence: HIGH when stripe is in deps and no constructEvent / Webhook.constructEvent
// call appears within proximity of the route. Conservative wording when
// the check fires — we say "no evidence found", not "your webhook is broken".

const WEBHOOK_PATH_REGEX =
  /\/(webhook|stripe-webhook|stripe\/webhook|callbacks?\/stripe|hooks\/stripe)\b/i;

const WEBHOOK_HANDLER_REGEX =
  /(app|router)\.(post|use)\s*\(\s*["'`][^"'`]*\/(webhook|stripe[\w-]*hook[\w-]*|hooks\/stripe)/i;

const SIGNATURE_VERIFY_REGEX =
  /\b(stripe\.webhooks\.constructEvent|Webhook\.constructEvent|webhooks\.constructEvent|verifyHeader\s*\(|constructEventAsync)\b/;

// Manual (raw HMAC) verification is valid too — Stripe's own docs describe
// computing the expected signature and comparing it in constant time. Treat a
// file that reads the `stripe-signature` header AND uses a constant-time
// compare (timingSafeEqual) as verifying, even without the SDK's
// constructEvent. A webhook that does NEITHER still flags, so this adds no
// false negative for the genuinely-unverified case.
const STRIPE_SIGNATURE_HEADER_REGEX = /stripe-signature/i;
const CONSTANT_TIME_COMPARE_REGEX = /\btimingSafeEqual\b/;

function verifiesManually(content: string): boolean {
  return (
    STRIPE_SIGNATURE_HEADER_REGEX.test(content) &&
    CONSTANT_TIME_COMPARE_REGEX.test(content)
  );
}

const RUNTIME_EXTS: ReadonlySet<string> = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
]);

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export async function checkPaymentsWebhook(
  ctx: CheckContext,
): Promise<Finding[]> {
  // Aggregate deps across EVERY package.json (basename match), so a monorepo
  // whose Stripe dep lives in artifacts/*/package.json or packages/* doesn't
  // escape the check by having a bare workspace-root manifest. Matches how
  // dependency-integrity / rate-limiting read manifests.
  const deps = new Set<string>();
  let sawPackageJson = false;
  for (const file of ctx.files) {
    if (path.basename(file.relPath) !== "package.json") continue;
    const raw = await readFileSafe(file);
    if (!raw) continue;
    sawPackageJson = true;
    try {
      const pkg = JSON.parse(raw) as PackageJson;
      for (const name of Object.keys(pkg.dependencies ?? {})) deps.add(name);
      for (const name of Object.keys(pkg.devDependencies ?? {})) deps.add(name);
    } catch {
      // ignore malformed manifests
    }
  }
  if (!sawPackageJson) return [];

  const usesStripe = deps.has("stripe") || deps.has("@stripe/stripe-js");
  if (!usesStripe) return [];

  // Find webhook-shaped routes. Conservative: only flag when we see
  // both an explicit /webhook path AND a route handler binding.
  const findings: Finding[] = [];

  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    if (isScanExempt(file.relPath)) continue;
    if (isLikelyNonRuntimePath(file.relPath)) continue;
    if (isUiLibraryPrimitive(file.relPath)) continue;

    const ext = path.extname(file.relPath).toLowerCase();
    if (!RUNTIME_EXTS.has(ext)) continue;

    const content = await readFileSafe(file);
    if (!content) continue;

    const handlerMatch = WEBHOOK_HANDLER_REGEX.exec(content);
    if (!handlerMatch) continue;

    const start = Math.max(0, handlerMatch.index - 200);
    const end = Math.min(content.length, handlerMatch.index + 2000);
    const window = content.slice(start, end);
    if (SIGNATURE_VERIFY_REGEX.test(window)) continue;
    // Module-scope raw-HMAC verify helpers commonly live outside the handler
    // window, so check the whole file for the manual-verification pattern.
    if (verifiesManually(content)) continue;

    const rel = relPosix(file.relPath);
    const line = findLine(content, handlerMatch.index);

    findings.push(
      makeFinding({
        checkId: "stripe-webhook-signature-missing",
        itemId: "payments",
        severity: "high",
        message:
          "Stripe is installed and a webhook-shaped route is bound here, but no `stripe.webhooks.constructEvent(...)` / signature-verify call was found within ~2000 characters of the handler. Without signature verification, anyone can POST a forged webhook to grant entitlements or trigger fulfillment. Owner must verify the verify call exists in the actual flow this route uses.",
        file: rel,
        line,
        evidence: `Webhook-shaped route bound at ${rel}:${line}. No 'stripe.webhooks.constructEvent' / 'Webhook.constructEvent' / 'verifyHeader(' call in the surrounding window.`,
      }),
    );
    return findings; // one finding per project is enough
  }

  // No webhook-shaped route found at all — don't flag. Stripe could be
  // used purely client-side (Elements / payment links) where webhooks
  // aren't the project's responsibility.
  return findings;
}
