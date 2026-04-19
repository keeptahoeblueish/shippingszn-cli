#!/usr/bin/env node
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as process from "node:process";

const MARKER = "<!-- shippingszn:pr-comment -->";
const SEVERITY_ORDER = ["critical", "high", "medium", "lower"];
const SEVERITY_LABEL = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  lower: "Lower",
};
const SEVERITY_EMOJI = {
  critical: "🛑",
  high: "⚠️",
  medium: "🟡",
  lower: "⚪",
};
const TOP_LIMIT = 10;

function escapeMd(text) {
  return String(text).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function formatLocation(finding) {
  if (!finding.file) return "";
  return finding.line ? `${finding.file}:${finding.line}` : finding.file;
}

function buildBody({ report, exitCode, parseError }) {
  const lines = [MARKER, "", "## shippingszn scan"];

  if (parseError) {
    lines.push(
      "",
      `The scanner did not produce a readable report (exit code \`${exitCode}\`).`,
      "Check the workflow logs and the uploaded `shippingszn-report` artifact.",
      "",
      "<details><summary>Parser error</summary>",
      "",
      "```",
      parseError,
      "```",
      "",
      "</details>",
    );
    return lines.join("\n") + "\n";
  }

  const totals = report.totals ?? { critical: 0, high: 0, medium: 0, lower: 0 };
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const totalCount = SEVERITY_ORDER.reduce(
    (sum, s) => sum + (totals[s] ?? 0),
    0,
  );

  if (totalCount === 0) {
    lines.push(
      "",
      "✅ No findings. Nice work — still walk through the full checklist before launch.",
      "",
      `_Scanned ${report.filesScanned ?? 0} files. Exit code \`${exitCode}\`._`,
    );
    return lines.join("\n") + "\n";
  }

  lines.push("", "| Severity | Count |", "| --- | ---: |");
  for (const sev of SEVERITY_ORDER) {
    lines.push(
      `| ${SEVERITY_EMOJI[sev]} ${SEVERITY_LABEL[sev]} | ${totals[sev] ?? 0} |`,
    );
  }

  const topGroups = ["critical", "high"];
  const top = findings
    .filter((f) => topGroups.includes(f.severity))
    .slice(0, TOP_LIMIT);
  if (top.length > 0) {
    lines.push(
      "",
      `### Top ${top.length} critical / high finding${top.length === 1 ? "" : "s"}`,
    );
    lines.push(
      "",
      "| Severity | Finding | Location | Checklist item |",
      "| --- | --- | --- | --- |",
    );
    for (const f of top) {
      const loc = formatLocation(f);
      const link = f.permalink
        ? `[${escapeMd(f.itemTitle ?? f.itemId)}](${f.permalink})`
        : escapeMd(f.itemTitle ?? f.itemId);
      lines.push(
        `| ${SEVERITY_EMOJI[f.severity]} ${SEVERITY_LABEL[f.severity] ?? f.severity} | ${escapeMd(f.message)} | ${loc ? `\`${escapeMd(loc)}\`` : ""} | ${link} |`,
      );
    }
    const remaining = totals.critical + totals.high - top.length;
    if (remaining > 0) {
      lines.push(
        "",
        `_…and ${remaining} more critical/high finding${remaining === 1 ? "" : "s"}._`,
      );
    }
  }

  const remainingMediumLower = (totals.medium ?? 0) + (totals.lower ?? 0);
  if (remainingMediumLower > 0) {
    lines.push(
      "",
      `Plus ${totals.medium ?? 0} medium and ${totals.lower ?? 0} lower findings — see the uploaded report for the full list.`,
    );
  }

  lines.push(
    "",
    `_Scanned ${report.filesScanned ?? 0} files. Exit code \`${exitCode}\`. Full JSON report is attached to this run as the \`shippingszn-report\` artifact._`,
  );

  return lines.join("\n") + "\n";
}

function main() {
  const reportPath = process.env.REPORT_PATH ?? ".shippingszn/report.json";
  const exitCode = process.env.SCAN_EXIT_CODE ?? "?";

  let report = null;
  let parseError = null;
  try {
    const raw = fs.readFileSync(reportPath, "utf8");
    report = JSON.parse(raw);
  } catch (err) {
    parseError = err instanceof Error ? err.message : String(err);
  }

  const body = buildBody({ report, exitCode, parseError });

  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "vibe-launch-comment-"));
  const outPath = path.join(outDir, "comment.md");
  fs.writeFileSync(outPath, body, "utf8");

  const ghOutput = process.env.GITHUB_OUTPUT;
  if (ghOutput) {
    fs.appendFileSync(ghOutput, `body_path=${outPath}\n`);
  } else {
    process.stdout.write(body);
  }
}

main();
