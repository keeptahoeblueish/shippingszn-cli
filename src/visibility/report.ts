import { mkdir, readdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { LocalVisibilityReport } from "./types.js";

export function renderVisibilityMarkdown(report: LocalVisibilityReport): string {
  const lines = [
    "# ShippingSZN AI Visibility Proof",
    "",
    `Target: ${report.targetUrl}`,
    `Generated: ${report.generatedAt}`,
    `Execution: local BYOK`,
    `Completed engines: ${report.enginesCompleted.join(", ") || "none"}`,
    `Unavailable engines: ${report.enginesMissing.join(", ") || "none"}`,
    "",
    "> ShippingSZN software is free. Provider calls may be charged to your own provider account.",
    "",
  ];
  for (const answer of report.answers) {
    lines.push(`## ${answer.engine}: ${answer.prompt}`, "", answer.text, "");
    if (answer.citations.length) {
      lines.push("Sources:");
      for (const citation of answer.citations) {
        lines.push(`- ${citation.title ? `${citation.title}: ` : ""}${citation.url}`);
      }
      lines.push("");
    }
  }
  return `${lines.join("\n")}\n`;
}

export async function writeVisibilityReport(
  report: LocalVisibilityReport,
  outputDir: string,
): Promise<{ jsonPath: string; markdownPath: string }> {
  const directory = resolve(outputDir);
  await mkdir(directory, { recursive: true });
  const existing = await readdir(directory);
  if (existing.length > 0) {
    throw new Error(`Output directory is not empty: ${directory}`);
  }
  const jsonPath = resolve(directory, "visibility-report.json");
  const markdownPath = resolve(directory, "visibility-report.md");
  await writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  await writeFile(markdownPath, renderVisibilityMarkdown(report), "utf8");
  return { jsonPath, markdownPath };
}
