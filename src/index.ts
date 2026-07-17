#!/usr/bin/env node
import * as path from "node:path";
import * as os from "node:os";
import * as process from "node:process";
import { promises as fs } from "node:fs";
import { createRequire } from "node:module";
import { ALL_CHECKS, type Finding } from "./checks.js";
import { listFiles, getTrackedFiles } from "./scan.js";
import { CHECKLIST_ITEMS, permalinkFor, type Severity } from "./items.js";
import { publishScan, detectStack } from "./publish.js";
import { uploadProof, type ProofUploadResult } from "./proof.js";
import {
  assessLaunchReadiness,
  normalizeLaunchFinding,
  type LaunchReadinessSource,
  type NormalizedLaunchFinding,
  type ScoreBandId,
} from "./vendor/launch-readiness/server.js";
import { CHECKLIST_PUBLIC as CHECKLIST } from "./vendor/checklist-data/public.js";

const UNTRACKED_DOWNGRADE: Record<Severity, Severity> = {
  critical: "lower",
  high: "lower",
  medium: "lower",
  lower: "lower",
};

const UNTRACKED_SUFFIX =
  " (Note: this file is not tracked in git — it can't leak through a repo push, so severity is softened. If you ever commit it or ship it in a public artifact, re-scan.)";

function applyTrackingAwareSeverity(
  findings: Finding[],
  tracked: Set<string> | null,
): Finding[] {
  if (!tracked) return findings;
  return findings.map((f) => {
    if (!f.file) return f;
    if (tracked.has(f.file)) return f;
    const nextSeverity = UNTRACKED_DOWNGRADE[f.severity];
    if (nextSeverity === f.severity) return f;
    return {
      ...f,
      severity: nextSeverity,
      message: f.message + UNTRACKED_SUFFIX,
    };
  });
}

interface CliOptions {
  cwd: string;
  json: boolean;
  baseUrl: string;
  help: boolean;
  version: boolean;
  noColor: boolean;
  proof: boolean;
  telemetry: boolean;
}

const DEFAULT_BASE_URL = "https://shippingszn.com";
const PKG_VERSION = ((): string => {
  const require = createRequire(import.meta.url);
  const pkg = require("../package.json") as { version: string };
  return pkg.version;
})();

class CliInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliInputError";
  }
}

function normalizeBaseUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new CliInputError(`Invalid --base-url value: ${raw}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new CliInputError("--base-url must use http:// or https://");
  }
  if (parsed.username || parsed.password) {
    throw new CliInputError("--base-url must not contain credentials");
  }
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "") || "/";
  return parsed.toString().replace(/\/+$/, "");
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    cwd: process.cwd(),
    json: false,
    baseUrl:
      process.env.SHIPPINGSZN_BASE_URL ??
      process.env.VIBE_LAUNCH_CHECK_BASE_URL ??
      DEFAULT_BASE_URL,
    help: false,
    version: false,
    noColor: !!process.env.NO_COLOR,
    proof: true,
    telemetry: true,
  };
  let targetWasSet = false;
  let positionalOnly = false;

  const requireValue = (flag: string, index: number): string => {
    const value = argv[index + 1];
    if (!value || value.startsWith("-")) {
      throw new CliInputError(`${flag} requires a value`);
    }
    return value;
  };

  const setTarget = (raw: string): void => {
    if (targetWasSet) {
      throw new CliInputError("Specify exactly one scan target");
    }
    opts.cwd = path.resolve(raw);
    targetWasSet = true;
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (positionalOnly) {
      setTarget(a);
      continue;
    }
    if (a === "--") {
      positionalOnly = true;
      continue;
    }
    if (a === "--help" || a === "-h") opts.help = true;
    else if (a === "--version" || a === "-v") opts.version = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--proof") opts.proof = true;
    else if (a === "--no-color") opts.noColor = true;
    else if (
      a === "--no-telemetry" ||
      a === "--no-wall" ||
      a === "--no-publish"
    )
      opts.telemetry = false;
    else if (a === "--base-url") {
      opts.baseUrl = requireValue(a, i);
      i += 1;
    } else if (a === "--cwd") {
      setTarget(requireValue(a, i));
      i += 1;
    } else if (a.startsWith("-")) {
      throw new CliInputError(`Unknown option: ${a}`);
    } else {
      setTarget(a);
    }
  }
  opts.baseUrl = normalizeBaseUrl(opts.baseUrl);
  return opts;
}

function color(enabled: boolean) {
  const wrap = (codes: string) => (s: string) =>
    enabled ? `\x1b[${codes}m${s}\x1b[0m` : s;
  return {
    bold: wrap("1"),
    dim: wrap("2"),
    red: wrap("31"),
    yellow: wrap("33"),
    blue: wrap("34"),
    cyan: wrap("36"),
    green: wrap("32"),
    magenta: wrap("35"),
    gray: wrap("90"),
  };
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "lower"];
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  lower: "LOWER",
};

function pluralize(count: number, singular: string, plural = `${singular}s`) {
  return count === 1 ? singular : plural;
}

function findingVerb(count: number) {
  return count === 1 ? "is" : "are";
}

function severityColor(
  sev: Severity,
  c: ReturnType<typeof color>,
): (s: string) => string {
  const map: Record<Severity, (s: string) => string> = {
    critical: c.red,
    high: c.yellow,
    medium: c.blue,
    lower: c.gray,
  };
  return map[sev];
}

// One-per-machine marker so the telemetry disclosure prints exactly once.
// Honors XDG / an override so tests can point it at a temp dir; defaults to
// ~/.config/shippingszn/seen.
function telemetryMarkerPath(): string {
  const base =
    process.env.SHIPPINGSZN_CONFIG_HOME ??
    process.env.XDG_CONFIG_HOME ??
    path.join(os.homedir(), ".config");
  return path.join(base, "shippingszn", "seen");
}

async function isFirstTelemetryRun(): Promise<boolean> {
  try {
    await fs.access(telemetryMarkerPath());
    return false;
  } catch {
    return true;
  }
}

// Best-effort. If the config dir is unwritable we fail open — the disclosure may
// print again next run, but the scan is never blocked.
async function markTelemetrySeen(): Promise<void> {
  const marker = telemetryMarkerPath();
  try {
    await fs.mkdir(path.dirname(marker), { recursive: true });
    await fs.writeFile(marker, `${new Date().toISOString()}\n`, "utf8");
  } catch {
    /* fail open */
  }
}

// Print the EXACT anonymous payload this run would send. Goes to stderr so it
// never corrupts --json stdout.
function printTelemetryDisclosure(info: {
  score: number;
  totals: Record<Severity, number>;
  filesScanned: number;
  scannerVersion: string;
  stack: string[];
}): void {
  const { score, totals, filesScanned, scannerVersion, stack } = info;
  const stackList = stack.length ? stack.join(", ") : "(none detected)";
  process.stderr.write(
    `\nshippingszn sends two anonymous telemetry requests per run by default:\n` +
      `1. A scan handoff (creates your /fix-kit link): each finding's severity,\n` +
      `   checklist item, file:line location, and a short evidence snippet from the\n` +
      `   matched line. Secret values are always redacted before upload.\n` +
      `2. An aggregate Wall ping. This run's aggregate payload:\n` +
      `   - score: ${score}\n` +
      `   - severity counts: ${totals.critical} critical, ${totals.high} high, ${totals.medium} medium, ${totals.lower} lower\n` +
      `   - files scanned: ${filesScanned}\n` +
      `   - scanner version: ${scannerVersion}\n` +
      `   - stack tags: ${stackList}\n` +
      `Neither request includes your repo URL, project name, full source files, or\n` +
      `unredacted secret values. Disable both with --no-telemetry (the CLI then runs\n` +
      `fully offline, zero network calls). This notice shows once per machine.\n\n`,
  );
}

type PublicNormalizedLaunchFinding = Omit<
  NormalizedLaunchFinding,
  | "fixInstructions"
  | "aiBuilderPrompt"
  | "verificationStep"
  | "fixPrompt"
  | "verify"
  | "whatFailed"
  | "whyItBlocksLaunch"
  | "body"
>;

type PublicFinding = Finding &
  PublicNormalizedLaunchFinding & {
    permalink: string;
    itemTitle: string;
  };

function printHelp(): void {
  process.stdout.write(
    `shippingszn v${PKG_VERSION}

Read-only launch inspector that checks the current project against high-signal
launch-readiness items from shippingszn.

Usage:
  npx shippingszn@latest [path] [options]

Options:
  --json                Output a machine-readable JSON summary (includes the
                        full findings array).
  --no-telemetry        Run fully offline. No scan handoff, no anonymous Wall
                        ping — zero network calls. (--no-wall is an alias.)
  --proof               Backward-compatible alias. Normal runs already return
                        a scan-specific Launch Fix Kit URL.
  --base-url <url>      Base URL used to build checkout and Fix Kit links.
                        (default: ${DEFAULT_BASE_URL})
  --cwd <path>          Directory to scan. Default: current working directory.
  --no-color            Disable ANSI colors in the human-readable summary.
  -h, --help            Show this help.
  -v, --version         Print version.

This is the FREE inspection and it is the full DIAGNOSIS: it prints every
finding — severity, the checklist item it maps to, the file and line, and what's
wrong — plus a 0-100 readiness score. The $49 Launch Fix Kit is the REMEDIATION
layer: per-finding fix instructions, prompts to paste straight into your AI
builder, the 58-item launch workbook, unlimited re-scans, and launch monitoring.
Read-only on disk. By default each run sends two anonymous requests: a scan
handoff carrying finding-level detail (severity, checklist item, file:line, and
a short evidence snippet — secret values always redacted) so checkout can carry
this exact scan into the Fix Kit, and an aggregate Wall ping (score, severity
counts, file count, scanner version, stack tags). Neither includes your repo
URL, project name, or full source files. Pass --no-telemetry to disable both.
Exit code non-zero if any critical findings.
`,
  );
}

interface Report {
  generatedAt: string;
  source: Extract<LaunchReadinessSource, "cli" | "github">;
  baseUrl: string;
  cwd: string;
  filesScanned: number;
  totals: Record<Severity, number>;
  launchReadiness: {
    score: number;
    rawScore: number;
    label: string;
    decision: string;
    decisionLabel: string;
    goNoGoLabel: string;
    confidence: string;
    coveragePenalty: number;
    coverageSummary: string;
    topNextStep: string;
    proofCreatePath: string;
    proofUploadHint: string;
    reportRecommended: boolean;
    proofUrl?: string;
    proofResultId?: string;
    badgeMarkdown?: string;
    reportUrl?: string;
    wallUrl?: string;
    proofUploadError?: string;
    wallPublishError?: string;
  };
  findings: PublicFinding[];
}

function scanSource(): Extract<LaunchReadinessSource, "cli" | "github"> {
  return process.env.GITHUB_ACTIONS === "true" ? "github" : "cli";
}

async function run(): Promise<number> {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    return 0;
  }
  if (opts.version) {
    process.stdout.write(`${PKG_VERSION}\n`);
    return 0;
  }

  const c = color(!opts.noColor && process.stdout.isTTY === true && !opts.json);

  const files = await listFiles(opts.cwd);
  const tracked = getTrackedFiles(opts.cwd);
  const ctx = { rootDir: opts.cwd, files };
  const all: Finding[] = [];
  for (const check of ALL_CHECKS) {
    try {
      const out = await check.run(ctx);
      all.push(...out);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      all.push({
        checkId: `${check.id}:error`,
        itemId: "ai-audit",
        severity: "lower",
        message: `Check ${check.id} crashed: ${msg}`,
      });
    }
  }

  const trimmedBaseUrl = opts.baseUrl.replace(/\/$/, "");
  const fixKitUrl = `${trimmedBaseUrl}/fix-kit`;
  const reportUrl = fixKitUrl; // legacy field name; same URL post-pivot
  const proofCreatePath = `${trimmedBaseUrl}/scan`;
  const proofUploadHint =
    "Normal runs automatically generate a scan-specific Launch Fix Kit URL.";

  const tracked_aware = applyTrackingAwareSeverity(all, tracked);

  const source = scanSource();
  const enriched = tracked_aware.map((f) => {
    const item = CHECKLIST_ITEMS[f.itemId];
    const itemTitle = item?.title ?? f.itemId;
    const permalink = permalinkFor(f.itemId, opts.baseUrl);
    const normalized = normalizeLaunchFinding(
      {
        severity: f.severity,
        title: itemTitle,
        body: f.message,
        message: f.message,
        evidence: f.evidence,
        file: f.file,
        line: f.line,
        permalink,
        itemTitle,
      },
      source,
    );
    return {
      ...f,
      severity: normalized.severity,
      title: normalized.title,
      body: normalized.body,
      message: normalized.message,
      evidence: normalized.evidence,
      confidence: normalized.confidence,
      ...(normalized.location ? { location: normalized.location } : {}),
      ...(normalized.file ? { file: normalized.file } : {}),
      ...(normalized.line ? { line: normalized.line } : {}),
      itemTitle,
      permalink,
    };
  });
  enriched.sort((a, b) => {
    const sa = SEVERITY_ORDER.indexOf(a.severity);
    const sb = SEVERITY_ORDER.indexOf(b.severity);
    if (sa !== sb) return sa - sb;
    if (a.itemId !== b.itemId) return a.itemId.localeCompare(b.itemId);
    return a.checkId.localeCompare(b.checkId);
  });

  const publicFindings = enriched.map((f): PublicFinding => {
    const { body: _body, ...publicFinding } = f;
    return publicFinding;
  });

  const totals: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    lower: 0,
  };
  for (const f of enriched) totals[f.severity]++;

  const assessment = assessLaunchReadiness({
    source,
    findings: enriched,
    counts: totals,
  });
  const launchReadiness: Report["launchReadiness"] = {
    score: assessment.score,
    rawScore: assessment.rawScore,
    label: assessment.label,
    decision: assessment.decision,
    decisionLabel: assessment.decisionLabel,
    goNoGoLabel: assessment.goNoGoLabel,
    confidence: assessment.confidence,
    coveragePenalty: assessment.coveragePenalty,
    coverageSummary: assessment.coverageSummary,
    topNextStep: assessment.topNextStep,
    proofCreatePath,
    proofUploadHint,
    reportRecommended: assessment.reportRecommended,
    ...(assessment.reportRecommended ? { reportUrl } : {}),
  };

  const report: Report = {
    generatedAt: new Date().toISOString(),
    source,
    baseUrl: opts.baseUrl,
    cwd: opts.cwd,
    filesScanned: files.length,
    totals,
    launchReadiness,
    findings: publicFindings,
  };

  // Telemetry is default-ON but transparent and opt-out-able. On the first run
  // on this machine, print the exact anonymous payload before any data leaves;
  // --no-telemetry skips both the scan handoff and the Wall ping entirely.
  if (opts.telemetry && (await isFirstTelemetryRun())) {
    printTelemetryDisclosure({
      score: launchReadiness.score,
      totals,
      filesScanned: files.length,
      scannerVersion: PKG_VERSION,
      stack: await detectStack(opts.cwd),
    });
    await markTelemetrySeen();
  }

  let proofResult: ProofUploadResult = { status: "skipped" };
  if (opts.telemetry && opts.proof) {
    proofResult = await uploadProof(
      {
        ...report,
        findings: enriched,
      },
      {
        baseUrl: opts.baseUrl,
        scannerVersion: PKG_VERSION,
      },
    );
    if (proofResult.status === "uploaded") {
      report.launchReadiness.proofUrl = proofResult.proofUrl;
      report.launchReadiness.proofResultId = proofResult.id;
      report.launchReadiness.badgeMarkdown = proofResult.badgeMarkdown;
      report.launchReadiness.reportUrl = proofResult.reportUrl;
      report.launchReadiness.wallUrl = proofResult.wallUrl;
      report.launchReadiness.wallPublishError = proofResult.wallPublishError;
    } else if (proofResult.status === "failed") {
      report.launchReadiness.proofUploadError =
        proofResult.error ?? "Proof upload failed.";
    }
  }

  // Anonymous aggregate signal for site stats and internal distribution data:
  // score + severity counts + file count + scanner version. No project name,
  // no paths, no finding-level detail. This is automatic for every normal CLI
  // run.
  // The only case we skip here is when the scan handoff already published the
  // aggregate entry as a side-effect of the upload (to avoid double counting).
  let publishResult: "published" | "skipped" | "failed" = "skipped";
  if (opts.telemetry) {
    try {
      const proofAlreadyPublishedWall =
        proofResult.status === "uploaded" && !!proofResult.wallUrl;
      if (!proofAlreadyPublishedWall) {
        publishResult = await publishScan(totals, files.length, {
          cwd: opts.cwd,
          baseUrl: opts.baseUrl,
          scannerVersion: PKG_VERSION,
          score: launchReadiness.score,
          label: launchReadiness.label,
        });
        if (publishResult === "published") {
          report.launchReadiness.wallUrl = `${opts.baseUrl.replace(/\/$/, "")}/wall`;
        }
      }
    } catch {
      /* never block on wall publish */
    }
  }

  // PIVOT 2026-07-16: the free CLI is the full DIAGNOSIS. Every finding — its
  // severity, the checklist item it maps to, the file:line, and the message —
  // prints locally and ships in default --json (`publicFindings`). What stays
  // paid is the REMEDIATION layer: fix instructions, AI-builder prompts, and
  // verification steps (stripped in `publicFindings`, still uploaded to
  // /api/scan-results so the Fix Kit can render them post-purchase).
  const automatedAreas = CHECKLIST.filter(
    (item) => item.cliCoverage === "automated",
  ).length;
  // The shared score is severity-banded: critical findings are the no-go band,
  // high findings are fix-first, medium findings are verify-first, and count
  // pressure moves the score inside that band. That keeps the number and
  // verdict from contradicting each other in the free CLI.
  const SCORE_BAND_LABEL: Record<ScoreBandId, string> = {
    blocked: "FIX NOW",
    fix_first: "FIX FIRST",
    verify_first: "VERIFY BEFORE LAUNCH",
    launchable: "LAUNCHABLE",
  };
  const CLI_BAND_ID: Record<
    ScoreBandId,
    "no_go" | "fix_first" | "verify_before_launch" | "launchable"
  > = {
    blocked: "no_go",
    fix_first: "fix_first",
    verify_first: "verify_before_launch",
    launchable: "launchable",
  };
  // Use the assessment's own band — bandFor(score, counts), which applies the
  // critical/high override — as the single source of truth. Re-deriving the
  // band from the score alone (scoreBandFor) can silently contradict the
  // library's decision if weights or band ranges ever change.
  const band = CLI_BAND_ID[assessment.band.id];
  const bandLabel = SCORE_BAND_LABEL[assessment.band.id];

  // Wall can be published via two paths: standalone (publishScan) or as a
  // side-effect of scan handoff upload. Surface a single, consistent wall.status
  // regardless of which path ran.
  const wallPublishedViaProof =
    proofResult.status === "uploaded" && !!proofResult.wallUrl;
  const wallStatus: "published" | "skipped" | "failed" = wallPublishedViaProof
    ? "published"
    : proofResult.status === "uploaded" && proofResult.wallPublishError
      ? "failed"
      : publishResult;
  const wallUrl = wallPublishedViaProof
    ? proofResult.wallUrl
    : publishResult === "published"
      ? `${trimmedBaseUrl}/wall`
      : undefined;
  const wallError = proofResult.wallPublishError;
  const scanSpecificUnlockUrl =
    proofResult.status === "uploaded" && proofResult.reportUrl
      ? proofResult.reportUrl
      : undefined;
  const unlockUrl = scanSpecificUnlockUrl ?? fixKitUrl;

  if (opts.json) {
    const scoreSummary = {
      score: launchReadiness.score,
      band,
      counts: { ...totals },
      filesScanned: files.length,
      coverage: {
        checksCompleted: automatedAreas,
        checklistAreas: CHECKLIST.length,
      },
      scannerVersion: PKG_VERSION,
      findings: publicFindings,
      unlockUrl,
      wall: {
        status: wallStatus,
        ...(wallUrl ? { url: wallUrl } : {}),
        ...(wallError ? { error: wallError } : {}),
      },
      scanHandoff: {
        status: proofResult.status,
        ...(proofResult.status === "uploaded"
          ? {
              resultId: proofResult.id,
              unlockUrl: proofResult.reportUrl,
            }
          : {}),
        ...(proofResult.status === "failed" && proofResult.error
          ? { error: proofResult.error }
          : {}),
      },
    };
    process.stdout.write(JSON.stringify(scoreSummary, null, 2) + "\n");
    return totals.critical > 0 ? 1 : 0;
  }

  // Full-diagnosis human output: verdict + score + counts + every finding
  // (severity, checklist item, file:line, message) + coverage + the remediation
  // CTA. The fixes themselves stay in the paid Fix Kit.
  const bandColor =
    band === "no_go"
      ? c.red
      : band === "fix_first"
        ? c.yellow
        : band === "verify_before_launch"
          ? c.blue
          : c.green;

  process.stdout.write(
    `\n${c.bold("shippingszn")} ${c.dim(`v${PKG_VERSION}`)}\n`,
  );
  process.stdout.write(c.dim(`Scanned ${files.length} files.\n\n`));

  process.stdout.write(
    `${c.bold("Verdict:")} ${bandColor(c.bold(bandLabel))}\n`,
  );
  process.stdout.write(
    `${c.bold("Readiness Score:")} ${launchReadiness.score}/100\n`,
  );
  process.stdout.write(c.dim("Higher is better.\n\n"));

  process.stdout.write(`${c.bold("Findings detected:")}\n`);
  process.stdout.write(`  ${c.red(`${totals.critical} critical`)}\n`);
  process.stdout.write(`  ${c.yellow(`${totals.high} high`)}\n`);
  process.stdout.write(`  ${c.blue(`${totals.medium} medium`)}\n`);
  process.stdout.write(`  ${c.gray(`${totals.lower} lower`)}\n\n`);

  const totalFindings =
    totals.critical + totals.high + totals.medium + totals.lower;
  if (totalFindings > 0) {
    if (totals.critical > 0) {
      process.stdout.write(c.red("Critical launch debt found.\n"));
      process.stdout.write(
        `This scan found ${totalFindings} ${pluralize(totalFindings, "issue")} that should be fixed before more public traffic.\n\n`,
      );
      process.stdout.write(`${c.bold("What that means:")}\n`);
      process.stdout.write(
        c.dim(
          "Critical launch debt can expose users, break signup or payment paths, or make the launch unsafe until fixed.\n\n",
        ),
      );
    } else {
      process.stdout.write("No critical findings found.\n");
      if (totals.high === 0) {
        process.stdout.write("No high findings found.\n");
      }
      process.stdout.write(
        `But ${totalFindings} ${pluralize(totalFindings, "issue")} ${findingVerb(totalFindings)} still holding this back from a clean day-1 posture.\n\n`,
      );
      process.stdout.write(`${c.bold("What that means:")}\n`);
      if (totals.high > 0) {
        process.stdout.write(
          c.dim(
            "High and medium launch gaps can expose trust gaps, break conversion moments, or make the project feel unfinished.\n\n",
          ),
        );
      } else if (totals.medium > 0) {
        process.stdout.write(
          c.dim(
            "Medium launch gaps usually will not crash the app, but they can make users hesitate, miss conversion moments, or make the project feel unfinished.\n\n",
          ),
        );
      } else {
        process.stdout.write(
          c.dim(
            "Lower launch gaps usually will not break the app, but they can still make the project feel rough or unfinished.\n\n",
          ),
        );
      }
    }
  }

  if (totalFindings > 0) {
    process.stdout.write(`${c.bold("Findings:")}\n`);
    for (const sev of SEVERITY_ORDER) {
      const group = publicFindings.filter((f) => f.severity === sev);
      if (group.length === 0) continue;
      const sc = severityColor(sev, c);
      process.stdout.write(
        `\n${sc(c.bold(SEVERITY_LABEL[sev]))} ${c.dim(`(${group.length})`)}\n`,
      );
      for (const f of group) {
        const loc = f.file ? (f.line ? `${f.file}:${f.line}` : f.file) : "";
        process.stdout.write(`  ${sc("•")} ${c.bold(f.itemTitle)}\n`);
        if (loc) process.stdout.write(`    ${c.cyan(loc)}\n`);
        process.stdout.write(`    ${c.dim(f.message)}\n`);
      }
    }
    process.stdout.write("\n");
  }

  process.stdout.write(`${c.bold("Coverage:")}\n`);
  process.stdout.write(
    c.dim(`  ${automatedAreas} launch-readiness checks completed\n\n`),
  );

  if (totalFindings === 0) {
    process.stdout.write(
      c.yellow("A clean scan is not a verified-safe app.\n"),
    );
    process.stdout.write(
      c.dim(
        "It means the scanner found nothing in the parts of your stack it can read statically. It does not confirm runtime auth, correct row-level-security scoping, rotated leaked keys, or your business logic — and it can only check what it recognizes, so an unusual stack may be lightly covered. Treat a clean result as a strong pre-launch signal, not a guarantee, and re-run it after any AI-assisted change.\n\n",
      ),
    );
  }

  if (totalFindings > 0) {
    process.stdout.write(
      `${c.bold("The findings above are free.")} ${c.dim("The $49 Launch Fix Kit is the fix layer:")}\n`,
    );
    process.stdout.write(
      c.dim(
        "  - Per-finding fix instructions\n" +
          "  - Prompts to paste straight into your AI builder\n" +
          "  - The 58-item launch workbook\n" +
          "  - Unlimited re-scans + launch monitoring\n",
      ),
    );
    process.stdout.write(`${c.bold("Get the fixes:")} ${c.cyan(unlockUrl)}\n`);
    if (scanSpecificUnlockUrl) {
      process.stdout.write(
        c.dim("  This exact scan carries into the Kit after checkout.\n\n"),
      );
    } else {
      process.stdout.write("\n");
    }
  } else {
    process.stdout.write(
      c.green("No automated findings detected — nothing to remediate.\n"),
    );
    process.stdout.write(
      `${c.bold("Get the Fix Kit:")} ${c.cyan(unlockUrl)}\n`,
    );
    process.stdout.write(
      c.dim(
        "  The 58-item launch workbook, owner-verification steps, re-scans, and\n" +
          "  monitoring for the gaps a static scan can't see.\n\n",
      ),
    );
  }

  if (proofResult.status === "failed") {
    process.stdout.write(
      c.dim(`(Scan handoff failed: ${proofResult.error ?? "unknown"})\n`),
    );
  }

  if (publishResult === "published") {
    process.stdout.write(
      c.dim("(Anonymous Wall stats sent: score + severity counts.)\n"),
    );
  }

  if (totals.critical > 0) {
    return 1;
  }
  return 0;
}

run().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(
      `shippingszn failed: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(2);
  },
);
