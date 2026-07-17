import type { Finding } from "./checks.js";
import type { Severity } from "./items.js";
import type { NormalizedLaunchFinding } from "./vendor/launch-readiness/index.js";

const PROOF_TIMEOUT_MS = 5000;
const MAX_FINDINGS = 100;

export type ProofUploadStatus = "uploaded" | "skipped" | "failed";

type PublicNormalizedLaunchFinding = Omit<
  NormalizedLaunchFinding,
  | "fixInstructions"
  | "aiBuilderPrompt"
  | "verificationStep"
  | "fixPrompt"
  | "verify"
  | "whatFailed"
  | "whyItBlocksLaunch"
>;

export type ProofFinding = Finding &
  PublicNormalizedLaunchFinding &
  Readonly<{
    permalink: string;
    itemTitle: string;
  }>;

export interface ProofReportInput {
  generatedAt: string;
  source?: "cli" | "github";
  cwd: string;
  filesScanned: number;
  totals: Record<Severity, number>;
  launchReadiness: {
    score: number;
    label: string;
    decision: string;
    decisionLabel: string;
    goNoGoLabel: string;
    confidence: string;
    topNextStep: string;
    reportRecommended: boolean;
    reportUrl?: string;
  };
  findings: ProofFinding[];
}

export interface ProofUploadResult {
  status: ProofUploadStatus;
  id?: string;
  proofUrl?: string;
  reportUrl?: string;
  badgeMarkdown?: string;
  wallUrl?: string;
  wallPublishError?: string;
  error?: string;
}

export interface ProofUploadOptions {
  baseUrl: string;
  scannerVersion: string;
}

function clampText(
  value: string | undefined,
  max: number,
  fallback = "",
): string {
  const text = value ?? fallback;
  return text.length > max ? text.slice(0, max - 3) + "..." : text;
}

function locationFromFinding(finding: ProofFinding): string | undefined {
  if (!finding.file) return undefined;
  return finding.line ? `${finding.file}:${finding.line}` : finding.file;
}

export function buildBadgeMarkdown(baseUrl: string, id: string, score: number) {
  const params = new URLSearchParams({
    scanResultId: id,
    theme: "dark",
  });
  const fixKitUrl = `${baseUrl}/fix-kit?${new URLSearchParams({ scanResultId: id }).toString()}`;
  return `[![shippingszn scan score: ${score}%](${baseUrl}/api/badge.svg?${params.toString()})](${fixKitUrl})`;
}

export function buildProofPayload(
  report: ProofReportInput,
  scannerVersion: string,
) {
  const counts = {
    critical: report.totals.critical,
    high: report.totals.high,
    medium: report.totals.medium,
    lower: report.totals.lower,
  };

  return {
    version: 1,
    source: report.source ?? ("cli" as const),
    scanner: "shippingszn" as const,
    targetName: "Anonymous CLI scan",
    score: report.launchReadiness.score,
    label: report.launchReadiness.label,
    decision: report.launchReadiness.decision,
    decisionLabel: report.launchReadiness.decisionLabel,
    goNoGoLabel: report.launchReadiness.goNoGoLabel,
    confidence: report.launchReadiness.confidence,
    checkedAt: report.generatedAt,
    counts,
    findings: report.findings.slice(0, MAX_FINDINGS).map((finding) => ({
      itemId: finding.itemId,
      severity: finding.severity,
      title: clampText(finding.itemTitle || finding.checkId, 160),
      body: clampText(finding.message, 3000),
      evidence: clampText(finding.evidence, 3000),
      confidence: finding.confidence,
      ...(locationFromFinding(finding)
        ? { location: clampText(locationFromFinding(finding)!, 500) }
        : {}),
      permalink: finding.permalink,
      itemTitle: clampText(finding.itemTitle, 160),
    })),
    filesScanned: report.filesScanned,
    topNextStep: clampText(report.launchReadiness.topNextStep, 1000),
    reportRecommended: report.launchReadiness.reportRecommended,
    ...(report.launchReadiness.reportUrl
      ? { reportUrl: report.launchReadiness.reportUrl }
      : {}),
    scannerVersion,
  };
}

function buildWallPayload(
  report: ProofReportInput,
  scanResultId: string,
  scannerVersion: string,
) {
  return {
    source: "cli" as const,
    scanResultId,
    score: report.launchReadiness.score,
    label: report.launchReadiness.label,
    filesScanned: report.filesScanned,
    findingsCritical: report.totals.critical,
    findingsHigh: report.totals.high,
    findingsMedium: report.totals.medium,
    findingsLower: report.totals.lower,
    scannerVersion,
  };
}

async function publishProofToWall(
  baseUrl: string,
  report: ProofReportInput,
  scanResultId: string,
  scannerVersion: string,
): Promise<{ wallUrl?: string; error?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROOF_TIMEOUT_MS);
  try {
    const res = await fetch(`${baseUrl}/api/wall`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": `shippingszn-cli/${scannerVersion}`,
      },
      body: JSON.stringify(
        buildWallPayload(report, scanResultId, scannerVersion),
      ),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      return { error: `Wall publish failed with HTTP ${res.status}.` };
    }
    return { wallUrl: `${baseUrl}/wall` };
  } catch (err) {
    clearTimeout(timer);
    return {
      error: `Wall publish failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

export async function uploadProof(
  report: ProofReportInput,
  opts: ProofUploadOptions,
): Promise<ProofUploadResult> {
  const baseUrl = opts.baseUrl.replace(/\/$/, "");
  const payload = buildProofPayload(report, opts.scannerVersion);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROOF_TIMEOUT_MS);

  try {
    const res = await fetch(`${baseUrl}/api/scan-results`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": `shippingszn-cli/${opts.scannerVersion}`,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!res.ok) {
      return {
        status: "failed",
        error: `Proof upload failed with HTTP ${res.status}.`,
      };
    }

    const body = (await res.json()) as { id?: unknown };
    const id = typeof body.id === "string" ? body.id : "";
    if (!id) {
      return {
        status: "failed",
        error: "Proof upload succeeded but the response did not include an id.",
      };
    }

    const wall = await publishProofToWall(
      baseUrl,
      report,
      id,
      opts.scannerVersion,
    );

    return {
      status: "uploaded",
      id,
      proofUrl: `${baseUrl}/proof/${encodeURIComponent(id)}`,
      reportUrl: `${baseUrl}/fix-kit?${new URLSearchParams({ scanResultId: id }).toString()}`,
      badgeMarkdown: buildBadgeMarkdown(
        baseUrl,
        id,
        report.launchReadiness.score,
      ),
      ...(wall.wallUrl ? { wallUrl: wall.wallUrl } : {}),
      ...(wall.error ? { wallPublishError: wall.error } : {}),
    };
  } catch (err) {
    clearTimeout(timer);
    return {
      status: "failed",
      error: `Proof upload failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
