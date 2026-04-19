#!/usr/bin/env node
import * as path from "node:path";
import * as process from "node:process";
import { ALL_CHECKS, type Finding } from "./checks.js";
import { listFiles, getTrackedFiles } from "./scan.js";
import { CHECKLIST_ITEMS, permalinkFor, type Severity } from "./items.js";

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
}

const DEFAULT_BASE_URL = "https://shippingszn.com";
const PKG_VERSION = "0.4.0";

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    cwd: process.cwd(),
    json: false,
    baseUrl: process.env.VIBE_LAUNCH_CHECK_BASE_URL ?? DEFAULT_BASE_URL,
    help: false,
    version: false,
    noColor: !!process.env.NO_COLOR,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") opts.help = true;
    else if (a === "--version" || a === "-v") opts.version = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--no-color") opts.noColor = true;
    else if (a === "--base-url") opts.baseUrl = argv[++i] ?? opts.baseUrl;
    else if (a === "--cwd") opts.cwd = path.resolve(argv[++i] ?? opts.cwd);
    else if (!a.startsWith("-")) opts.cwd = path.resolve(a);
  }
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

function printHelp(): void {
  process.stdout.write(
    `shippingszn v${PKG_VERSION}

Read-only scanner that checks the current project against a small set of
high-signal items from the Vibe Coder Launch Checklist.

Usage:
  npx shippingszn [path] [options]

Options:
  --json                Output a machine-readable JSON report.
  --base-url <url>      Base URL used to build links back to checklist items.
                        (default: ${DEFAULT_BASE_URL})
  --cwd <path>          Directory to scan. Default: current working directory.
  --no-color            Disable ANSI colors in the human-readable report.
  -h, --help            Show this help.
  -v, --version         Print version.

The scanner only reads files. It never writes, modifies, or deletes anything.
Exit code is non-zero if any Critical findings are detected.
`,
  );
}

interface Report {
  generatedAt: string;
  baseUrl: string;
  cwd: string;
  filesScanned: number;
  totals: Record<Severity, number>;
  findings: Array<Finding & { permalink: string; itemTitle: string }>;
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

  const tracked_aware = applyTrackingAwareSeverity(all, tracked);

  const enriched = tracked_aware.map((f) => {
    const item = CHECKLIST_ITEMS[f.itemId];
    return {
      ...f,
      itemTitle: item?.title ?? f.itemId,
      permalink: permalinkFor(f.itemId, opts.baseUrl),
    };
  });
  enriched.sort((a, b) => {
    const sa = SEVERITY_ORDER.indexOf(a.severity);
    const sb = SEVERITY_ORDER.indexOf(b.severity);
    if (sa !== sb) return sa - sb;
    if (a.itemId !== b.itemId) return a.itemId.localeCompare(b.itemId);
    return a.checkId.localeCompare(b.checkId);
  });

  const totals: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    lower: 0,
  };
  for (const f of enriched) totals[f.severity]++;

  const report: Report = {
    generatedAt: new Date().toISOString(),
    baseUrl: opts.baseUrl,
    cwd: opts.cwd,
    filesScanned: files.length,
    totals,
    findings: enriched,
  };

  if (opts.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    return totals.critical > 0 ? 1 : 0;
  }

  // Human-readable report
  const sevColor = (s: Severity) => {
    if (s === "critical") return c.red;
    if (s === "high") return c.yellow;
    if (s === "medium") return c.blue;
    return c.gray;
  };

  process.stdout.write(
    `\n${c.bold("shippingszn")} ${c.dim(`v${PKG_VERSION}`)}\n`,
  );
  process.stdout.write(
    c.dim(`Scanned ${files.length} files in ${opts.cwd}\n\n`),
  );

  if (enriched.length === 0) {
    process.stdout.write(
      c.green(
        "✓ No findings. Nice work — still walk through the full checklist before launch.\n\n",
      ),
    );
    return 0;
  }

  // Strip ASCII control characters (including ESC) so a maliciously-named
  // file or matched secret slice cannot inject ANSI escape sequences into
  // the operator's terminal.
  const safe = (s: string): string => s.replace(/[\x00-\x1f\x7f]/g, "?");

  for (const sev of SEVERITY_ORDER) {
    const group = enriched.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    process.stdout.write(
      `${sevColor(sev)(c.bold(`${SEVERITY_LABEL[sev]} (${group.length})`))}\n`,
    );
    for (const f of group) {
      const loc = f.file
        ? ` ${c.dim(`— ${safe(f.file)}${f.line ? `:${f.line}` : ""}`)}`
        : "";
      process.stdout.write(`  ${c.bold("•")} ${safe(f.message)}${loc}\n`);
      if (f.evidence) {
        process.stdout.write(`    ${c.dim(`evidence: ${safe(f.evidence)}`)}\n`);
      }
      process.stdout.write(
        `    ${c.cyan(`→ ${safe(f.itemTitle)}`)} ${c.dim(f.permalink)}\n`,
      );
    }
    process.stdout.write("\n");
  }

  process.stdout.write(
    `${c.bold("Summary:")} ${c.red(`${totals.critical} critical`)}, ${c.yellow(`${totals.high} high`)}, ${c.blue(`${totals.medium} medium`)}, ${c.gray(`${totals.lower} lower`)}\n`,
  );
  if (totals.critical > 0) {
    process.stdout.write(
      c.red("\nCritical findings detected. Exiting with code 1.\n"),
    );
    return 1;
  }
  process.stdout.write(
    c.dim(
      "\nNo critical findings. Open the linked checklist items to dig deeper.\n",
    ),
  );
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
