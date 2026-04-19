#!/usr/bin/env node
import { promises as fs } from "node:fs";
import { existsSync, appendFileSync } from "node:fs";

const SEVERITIES = ["critical", "high", "medium", "lower"];

function emptyTotals() {
  return { critical: 0, high: 0, medium: 0, lower: 0 };
}

function appendOutputs(pairs) {
  const out = process.env.GITHUB_OUTPUT;
  if (!out) {
    for (const [k, v] of Object.entries(pairs)) {
      process.stdout.write(`${k}=${v}\n`);
    }
    return;
  }
  const lines = [];
  for (const [k, v] of Object.entries(pairs)) {
    const s = String(v);
    if (s.includes("\n")) {
      const delim = `EOF_${k}_${Date.now()}`;
      lines.push(`${k}<<${delim}\n${s}\n${delim}`);
    } else {
      lines.push(`${k}=${s}`);
    }
  }
  appendFileSync(out, lines.join("\n") + "\n");
}

function buildSpikeSummary({ previous, current, deltas }) {
  const lines = [];
  lines.push("Scanner findings increased on the main branch.");
  lines.push("");
  lines.push(
    `- Commit: \`${current.shortCommit || current.commit || "unknown"}\``,
  );
  if (current.runUrl) lines.push(`- Run: ${current.runUrl}`);
  lines.push("");
  lines.push("| Severity | Previous | Current | Δ |");
  lines.push("| --- | ---: | ---: | ---: |");
  for (const sev of SEVERITIES) {
    const prev = previous?.totals?.[sev] ?? 0;
    const curr = current.totals[sev];
    const delta = deltas[sev];
    const sign = delta > 0 ? `+${delta}` : `${delta}`;
    lines.push(`| ${sev} | ${prev} | ${curr} | ${sign} |`);
  }
  if (previous?.shortCommit || previous?.commit) {
    lines.push("");
    lines.push(
      `Comparing against previous main-branch scan at \`${previous.shortCommit || previous.commit}\`.`,
    );
  }
  return lines.join("\n");
}

const reportName = process.env.REPORT_NAME;
const recordedAt = process.env.DATE_ISO;
const commit = process.env.COMMIT_SHA || "";
const runId = process.env.RUN_ID;
const runNumber = Number(process.env.RUN_NUMBER);
const repo = process.env.REPO;
const serverUrl = process.env.SERVER_URL;

if (!reportName) {
  console.error("REPORT_NAME env var is required.");
  process.exit(1);
}

const report = JSON.parse(await fs.readFile(reportName, "utf8"));
const totals = report.totals || {};

const entry = {
  generatedAt: report.generatedAt,
  recordedAt,
  commit,
  shortCommit: commit.slice(0, 7),
  runId,
  runNumber,
  runUrl: `${serverUrl}/${repo}/actions/runs/${runId}`,
  reportPath: reportName,
  filesScanned: report.filesScanned ?? 0,
  findingsCount: Array.isArray(report.findings) ? report.findings.length : 0,
  totals: {
    critical: totals.critical ?? 0,
    high: totals.high ?? 0,
    medium: totals.medium ?? 0,
    lower: totals.lower ?? 0,
  },
};

const historyPath = "history.json";
let history = [];
if (existsSync(historyPath)) {
  try {
    const parsed = JSON.parse(await fs.readFile(historyPath, "utf8"));
    if (Array.isArray(parsed)) history = parsed;
  } catch {
    history = [];
  }
}

const previous = history.length ? history[history.length - 1] : null;

const deltas = emptyTotals();
for (const sev of SEVERITIES) {
  const prev = previous?.totals?.[sev] ?? 0;
  deltas[sev] = entry.totals[sev] - prev;
}
const spike = previous !== null && (deltas.critical > 0 || deltas.high > 0);

history.push(entry);
history.sort((a, b) =>
  String(a.recordedAt).localeCompare(String(b.recordedAt)),
);
await fs.writeFile(historyPath, JSON.stringify(history, null, 2) + "\n");

const recent = history.slice(-30).reverse();
const lines = [];
lines.push("# shippingszn history");
lines.push("");
lines.push(
  "Severity counts from each scanner run on `main`. Newest first; the latest 30 runs are shown below. " +
    "Full history lives in [`history.json`](./history.json) and full reports under [`reports/`](./reports).",
);
lines.push("");
const latest = recent[0];
if (latest) {
  lines.push(
    `**Latest:** ${latest.recordedAt} — \`${latest.shortCommit}\` — ` +
      `critical ${latest.totals.critical}, high ${latest.totals.high}, ` +
      `medium ${latest.totals.medium}, lower ${latest.totals.lower} ` +
      `([run](${latest.runUrl}))`,
  );
  lines.push("");
}
lines.push(
  "| Recorded (UTC) | Commit | Critical | High | Medium | Lower | Findings | Files | Run |",
);
lines.push("|---|---|---:|---:|---:|---:|---:|---:|---|");
for (const e of recent) {
  lines.push(
    `| ${e.recordedAt} | \`${e.shortCommit}\` | ${e.totals.critical} | ${e.totals.high} | ` +
      `${e.totals.medium} | ${e.totals.lower} | ${e.findingsCount} | ${e.filesScanned} | ` +
      `[#${e.runNumber}](${e.runUrl}) |`,
  );
}
lines.push("");
await fs.writeFile("README.md", lines.join("\n"));

const summary = spike
  ? buildSpikeSummary({ previous, current: entry, deltas })
  : "";
const issueTitle = spike
  ? `shippingszn: scanner findings increased on main (+${Math.max(deltas.critical, 0)} critical, +${Math.max(deltas.high, 0)} high)`
  : "";

appendOutputs({
  spike: spike ? "true" : "false",
  critical_delta: String(deltas.critical),
  high_delta: String(deltas.high),
  medium_delta: String(deltas.medium),
  lower_delta: String(deltas.lower),
  critical_total: String(entry.totals.critical),
  high_total: String(entry.totals.high),
  previous_commit: previous?.commit ?? "",
  issue_title: issueTitle,
  summary,
});

console.log(
  `Appended history entry for ${entry.shortCommit} (run #${entry.runNumber}); spike=${spike}.`,
);
