/**
 * Prompt-free launch-readiness core for the public CLI.
 *
 * Keep this module standalone. The public package exporter copies it verbatim,
 * so it must never import the paid report builder, checklist content, or
 * remediation prompt code from ./index.ts or ./server.ts.
 */

export type LaunchReadinessSource = "url" | "cli" | "github" | "manual";

export type LaunchSeverity =
  | "fatal"
  | "critical"
  | "error"
  | "high"
  | "medium"
  | "warning"
  | "low"
  | "lower"
  | "info";

export type CanonicalSeverity = "critical" | "high" | "medium" | "lower";
export type LaunchDecision = "no-go" | "fix-first" | "verify-first" | "go";
export type LaunchConfidence = "low" | "medium" | "high";
export type ScoreBandId =
  | "blocked"
  | "fix_first"
  | "verify_first"
  | "launchable";
export type LaunchCoverageStatus = "checked" | "partial" | "not_checked";
export type LaunchCoverageAreaId =
  | "public_surface"
  | "repo_static"
  | "secrets"
  | "auth"
  | "paid_api"
  | "deployment"
  | "content"
  | "proof";

export interface LaunchReadinessCounts {
  critical: number;
  high: number;
  medium: number;
  lower: number;
}

export interface LaunchFindingInput {
  itemId?: string;
  severity?: LaunchSeverity | string;
  title?: string;
  body?: string;
  message?: string;
  evidence?: string;
  confidence?: LaunchConfidence | string;
  location?: string;
  file?: string;
  line?: number;
  permalink?: string;
  itemTitle?: string;
  whatFailed?: string;
  whyItBlocksLaunch?: string;
  fixInstructions?: string;
  fixPrompt?: string;
  aiBuilderPrompt?: string;
  verify?: string;
  verificationStep?: string;
}

export interface NormalizedLaunchFinding {
  itemId?: string;
  severity: CanonicalSeverity;
  title: string;
  whatFailed: string;
  whyItBlocksLaunch: string;
  fixInstructions: string;
  aiBuilderPrompt: string;
  verificationStep: string;
  evidence: string;
  confidence: LaunchConfidence;
  body: string;
  message: string;
  fixPrompt: string;
  verify: string;
  location?: string;
  file?: string;
  line?: number;
  permalink?: string;
  itemTitle?: string;
}

export interface ScoreBand {
  id: ScoreBandId;
  minScore: number;
  maxScore: number;
  label: string;
  decision: LaunchDecision;
  goNoGoLabel: string;
}

export interface LaunchCoverageArea {
  id: LaunchCoverageAreaId;
  label: string;
  status: LaunchCoverageStatus;
  evidence: string;
  confidence: LaunchConfidence;
}

export interface LaunchReadinessAssessment {
  score: number;
  rawScore: number;
  label: string;
  decision: string;
  decisionLabel: string;
  launchDecision: LaunchDecision;
  goNoGoLabel: string;
  band: ScoreBand;
  counts: LaunchReadinessCounts;
  severityWeights: Record<CanonicalSeverity, number>;
  weightedPenalty: number;
  coveragePenalty: number;
  coverage: LaunchCoverageArea[];
  coverageSummary: string;
  checkedAreas: LaunchCoverageArea[];
  uncheckedAreas: LaunchCoverageArea[];
  topNextStep: string;
  reportRecommended: boolean;
  confidence: LaunchConfidence;
  blockers: NormalizedLaunchFinding[];
  findings: NormalizedLaunchFinding[];
}

export interface LaunchReadinessInput {
  source?: LaunchReadinessSource;
  findings?: LaunchFindingInput[];
  counts?: Partial<Record<CanonicalSeverity, number>>;
  targetName?: string | null;
  targetUrl?: string | null;
  checkedAt?: string;
}

export const SEVERITY_WEIGHTS: Record<CanonicalSeverity, number> = {
  critical: 35,
  high: 22,
  medium: 10,
  lower: 5,
};

export const SCORE_BANDS: ScoreBand[] = [
  {
    id: "blocked",
    minScore: 0,
    maxScore: 59,
    label: "Fix now",
    decision: "no-go",
    goNoGoLabel: "Fix now",
  },
  {
    id: "fix_first",
    minScore: 60,
    maxScore: 79,
    label: "Fix-first",
    decision: "fix-first",
    goNoGoLabel: "Fix first",
  },
  {
    id: "verify_first",
    minScore: 80,
    maxScore: 89,
    label: "Verify before launch",
    decision: "verify-first",
    goNoGoLabel: "Verify first",
  },
  {
    id: "launchable",
    minScore: 90,
    maxScore: 100,
    label: "Launchable",
    decision: "go",
    goNoGoLabel: "Go",
  },
];

const SOURCE_SCORE_CAP: Record<LaunchReadinessSource, number> = {
  url: 88,
  cli: 100,
  github: 100,
  manual: 72,
};

const COVERAGE_LABELS: Record<LaunchCoverageAreaId, string> = {
  public_surface: "Public launch surface",
  repo_static: "Repository static scan",
  secrets: "Secrets and config exposure",
  auth: "Auth, OTP, and private surfaces",
  paid_api: "Paid API and abuse risk",
  deployment: "Deployment and runtime config",
  content: "Launch content and metadata",
  proof: "Proof/report handoff",
};

const SEVERITY_RANK: Record<CanonicalSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  lower: 3,
};

function clampText(value: string | undefined, fallback: string, max = 4000) {
  const trimmed = value?.trim();
  const out = trimmed || fallback;
  return out.length > max ? `${out.slice(0, max - 3)}...` : out;
}

function optionalText(value: string | undefined, max = 4000): string {
  const trimmed = value?.trim() ?? "";
  return trimmed.length > max ? `${trimmed.slice(0, max - 3)}...` : trimmed;
}

function clampCount(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return 0;
  return Math.max(0, Math.round(value));
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

export function canonicalSeverity(value: unknown): CanonicalSeverity {
  if (value === "fatal" || value === "error" || value === "critical") {
    return "critical";
  }
  if (value === "high") return "high";
  if (value === "medium" || value === "warning") return "medium";
  return "lower";
}

export function emptyLaunchReadinessCounts(): LaunchReadinessCounts {
  return { critical: 0, high: 0, medium: 0, lower: 0 };
}

export function normalizeLaunchCounts(
  counts?: Partial<Record<CanonicalSeverity, number>>,
): LaunchReadinessCounts {
  return {
    critical: clampCount(counts?.critical),
    high: clampCount(counts?.high),
    medium: clampCount(counts?.medium),
    lower: clampCount(counts?.lower),
  };
}

export function countLaunchFindings(
  findings: readonly LaunchFindingInput[],
): LaunchReadinessCounts {
  const counts = emptyLaunchReadinessCounts();
  for (const finding of findings) {
    counts[canonicalSeverity(finding.severity)] += 1;
  }
  return counts;
}

function confidenceForSource(source: LaunchReadinessSource): LaunchConfidence {
  if (source === "url") return "medium";
  if (source === "manual") return "low";
  return "high";
}

function normalizeConfidence(
  value: unknown,
  fallback: LaunchConfidence,
): LaunchConfidence {
  return value === "low" || value === "medium" || value === "high"
    ? value
    : fallback;
}

function sourceLabel(source: LaunchReadinessSource): string {
  if (source === "github") return "GitHub Action scan";
  if (source === "cli") return "CLI scan";
  if (source === "url") return "public URL scan";
  return "manual intake";
}

function coverageArea(
  id: LaunchCoverageAreaId,
  status: LaunchCoverageStatus,
  evidence: string,
  confidence?: LaunchConfidence,
): LaunchCoverageArea {
  return {
    id,
    label: COVERAGE_LABELS[id],
    status,
    evidence,
    confidence:
      confidence ??
      (status === "checked" ? "high" : status === "partial" ? "medium" : "low"),
  };
}

function coverageForSource(source: LaunchReadinessSource): LaunchCoverageArea[] {
  if (source === "url") {
    return [
      coverageArea(
        "public_surface",
        "checked",
        "Fetched the public URL and evaluated launch-page basics.",
        "medium",
      ),
      coverageArea(
        "repo_static",
        "not_checked",
        "No repository files were scanned from the public URL path.",
      ),
      coverageArea(
        "secrets",
        "not_checked",
        "Repository config checks require the CLI or GitHub Action.",
      ),
      coverageArea(
        "auth",
        "not_checked",
        "Private authentication behavior cannot be proven from a public fetch.",
      ),
      coverageArea(
        "paid_api",
        "not_checked",
        "Provider controls require repository or operator context.",
      ),
      coverageArea(
        "deployment",
        "partial",
        "HTTPS and response behavior were checked; runtime config was not.",
      ),
      coverageArea(
        "content",
        "checked",
        "Public metadata and launch-page signals were checked.",
        "medium",
      ),
      coverageArea(
        "proof",
        "checked",
        "The score can be stored as a launch-readiness handoff.",
        "medium",
      ),
    ];
  }

  if (source === "cli" || source === "github") {
    const isGithub = source === "github";
    return [
      coverageArea(
        "public_surface",
        "partial",
        "Repository signals were scanned; live behavior still needs a URL check.",
      ),
      coverageArea(
        "repo_static",
        "checked",
        isGithub
          ? "GitHub Actions scanned checked-out repository files."
          : "The local CLI scanned repository files from the project root.",
      ),
      coverageArea(
        "secrets",
        "checked",
        "Common committed secret and config exposure patterns were scanned.",
      ),
      coverageArea(
        "auth",
        "partial",
        "Static auth signals were checked; runtime behavior still needs verification.",
      ),
      coverageArea(
        "paid_api",
        "partial",
        "Static provider-control signals were checked; live controls remain unverified.",
      ),
      coverageArea(
        "deployment",
        "partial",
        "Deploy-facing files were scanned; hosted settings may be outside the repo.",
      ),
      coverageArea(
        "content",
        "checked",
        "Launch metadata, public assets, and placeholder signals were scanned.",
      ),
      coverageArea(
        "proof",
        "checked",
        "The result can create a locked scan handoff and aggregate proof.",
      ),
    ];
  }

  return (Object.keys(COVERAGE_LABELS) as LaunchCoverageAreaId[]).map((id) =>
    coverageArea(
      id,
      id === "proof" ? "checked" : "partial",
      id === "proof"
        ? "The result can be stored as a launch-readiness handoff."
        : "Manual evidence is not an automated verification.",
      "low",
    ),
  );
}

function coverageSummary(
  source: LaunchReadinessSource,
  coverage: readonly LaunchCoverageArea[],
): string {
  const checked = coverage.filter((area) => area.status === "checked").length;
  const partial = coverage.filter((area) => area.status === "partial").length;
  const missing = coverage.filter((area) => area.status === "not_checked");
  if (missing.length === 0) {
    return `${sourceLabel(source)} covered ${checked} readiness areas with ${partial} areas requiring owner verification.`;
  }
  return `${sourceLabel(source)} covered ${checked} readiness areas, partially covered ${partial}, and left ${missing.map((area) => area.label).join(", ")} unverified.`;
}

function locationLine(finding: LaunchFindingInput): string {
  if (finding.location?.trim()) return finding.location.trim();
  if (!finding.file?.trim()) return "";
  return finding.line
    ? `${finding.file.trim()}:${finding.line}`
    : finding.file.trim();
}

export function normalizeLaunchFinding(
  finding: LaunchFindingInput,
  source: LaunchReadinessSource = "manual",
): NormalizedLaunchFinding {
  const severity = canonicalSeverity(finding.severity);
  const title = clampText(
    finding.title ?? finding.itemTitle,
    "Launch-readiness finding",
    160,
  );
  const body = clampText(
    finding.body ?? finding.message,
    "The local scan detected a launch-readiness signal.",
    3000,
  );
  const location = locationLine(finding);
  const evidence = clampText(
    finding.evidence,
    location ? `Observed at ${location}.` : body,
    3000,
  );
  const fixInstructions = optionalText(
    finding.fixInstructions ?? finding.fixPrompt,
  );
  const aiBuilderPrompt = optionalText(finding.aiBuilderPrompt);
  const verificationStep = optionalText(
    finding.verificationStep ?? finding.verify,
  );

  return {
    severity,
    title,
    whatFailed: clampText(finding.whatFailed, body, 3000),
    whyItBlocksLaunch: clampText(finding.whyItBlocksLaunch, body, 3000),
    fixInstructions,
    aiBuilderPrompt,
    verificationStep,
    evidence,
    confidence: normalizeConfidence(
      finding.confidence,
      confidenceForSource(source),
    ),
    body,
    message: body,
    fixPrompt: aiBuilderPrompt,
    verify: verificationStep,
    ...(finding.itemId ? { itemId: finding.itemId } : {}),
    ...(location ? { location } : {}),
    ...(finding.file ? { file: finding.file } : {}),
    ...(finding.line ? { line: finding.line } : {}),
    ...(finding.permalink ? { permalink: finding.permalink } : {}),
    ...(finding.itemTitle ? { itemTitle: finding.itemTitle } : {}),
  };
}

export function prioritizeLaunchFindings(
  findings: readonly LaunchFindingInput[],
  source: LaunchReadinessSource = "manual",
): NormalizedLaunchFinding[] {
  return findings
    .map((finding) => normalizeLaunchFinding(finding, source))
    .sort((left, right) => {
      const bySeverity =
        SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity];
      return bySeverity || left.title.localeCompare(right.title);
    });
}

function scoreWithinBand(rawScore: number, band: ScoreBand): number {
  return Math.max(band.minScore, Math.min(band.maxScore, rawScore));
}

function severityBandedScore(
  rawScore: number,
  counts: LaunchReadinessCounts,
): number {
  if (counts.critical > 0) return Math.min(rawScore, SCORE_BANDS[0]!.maxScore);
  if (counts.high > 0) return scoreWithinBand(rawScore, SCORE_BANDS[1]!);
  if (counts.medium > 0) return scoreWithinBand(rawScore, SCORE_BANDS[2]!);
  if (counts.lower > 0) return scoreWithinBand(rawScore, SCORE_BANDS[3]!);
  return SCORE_BANDS[3]!.maxScore;
}

function scoreFromCounts(
  counts: LaunchReadinessCounts,
  source: LaunchReadinessSource,
) {
  const weightedPenalty =
    counts.critical * SEVERITY_WEIGHTS.critical +
    counts.high * SEVERITY_WEIGHTS.high +
    counts.medium * SEVERITY_WEIGHTS.medium +
    counts.lower * SEVERITY_WEIGHTS.lower;
  const rawScore = clampScore(100 - weightedPenalty);
  const severityScore = severityBandedScore(rawScore, counts);
  const score = Math.min(severityScore, SOURCE_SCORE_CAP[source]);
  return {
    score,
    rawScore,
    weightedPenalty,
    coveragePenalty: Math.max(0, severityScore - score),
  };
}

function scoreBandFor(score: number): ScoreBand {
  return (
    SCORE_BANDS.find(
      (band) => score >= band.minScore && score <= band.maxScore,
    ) ?? SCORE_BANDS[0]!
  );
}

function bandFor(score: number, counts: LaunchReadinessCounts): ScoreBand {
  if (counts.critical > 0) return SCORE_BANDS[0]!;
  if (counts.high > 0) return SCORE_BANDS[1]!;
  return scoreBandFor(score);
}

function decisionText(
  band: ScoreBand,
  counts: LaunchReadinessCounts,
  source: LaunchReadinessSource,
): string {
  if (counts.critical > 0) {
    return `Fix now. ${counts.critical} critical finding${counts.critical === 1 ? "" : "s"} should be resolved before more public traffic.`;
  }
  if (counts.high > 0) return "Fix the high-risk launch gaps before launch.";
  if (counts.medium > 0 || counts.lower > 0) {
    return `No critical or high finding was detected, but the remaining gaps should be verified before treating the ${sourceLabel(source)} as ready.`;
  }
  if (source === "url") {
    return "No public-page critical findings were found. Run the repository scan next.";
  }
  return `${band.goNoGoLabel}: no scan-detected critical findings were found.`;
}

function topNextStep(
  counts: LaunchReadinessCounts,
  source: LaunchReadinessSource,
): string {
  if (counts.critical > 0 || counts.high > 0) {
    return "Open the paid Launch Fix Kit for the exact highest-severity finding.";
  }
  if (source === "url") return "Run the repository scan next.";
  if (counts.medium > 0 || counts.lower > 0) {
    return "Open the paid Launch Fix Kit for the remaining finding details.";
  }
  return "Monitor the first production traffic and rescan after changes.";
}

function aggregateConfidence(
  source: LaunchReadinessSource,
  findings: readonly NormalizedLaunchFinding[],
): LaunchConfidence {
  if (findings.some((finding) => finding.confidence === "low")) return "low";
  if (source === "url") return "medium";
  return "high";
}

export function assessLaunchReadiness(
  input: LaunchReadinessInput,
): LaunchReadinessAssessment {
  const source = input.source ?? "manual";
  const findings = prioritizeLaunchFindings(input.findings ?? [], source);
  const counts = input.counts
    ? normalizeLaunchCounts(input.counts)
    : countLaunchFindings(findings);
  const { score, rawScore, weightedPenalty, coveragePenalty } = scoreFromCounts(
    counts,
    source,
  );
  const band = bandFor(score, counts);
  const coverage = coverageForSource(source);
  const checkedAreas = coverage.filter((area) => area.status === "checked");
  const uncheckedAreas = coverage.filter((area) => area.status !== "checked");
  const blockers = findings.filter(
    (finding) => finding.severity === "critical" || finding.severity === "high",
  );

  return {
    score,
    rawScore,
    label: band.label,
    decision: decisionText(band, counts, source),
    decisionLabel: band.label,
    launchDecision: band.decision,
    goNoGoLabel: band.goNoGoLabel,
    band,
    counts,
    severityWeights: SEVERITY_WEIGHTS,
    weightedPenalty,
    coveragePenalty,
    coverage,
    coverageSummary: coverageSummary(source, coverage),
    checkedAreas,
    uncheckedAreas,
    topNextStep: topNextStep(counts, source),
    reportRecommended:
      counts.critical > 0 || counts.high > 0 || coveragePenalty > 0,
    confidence: aggregateConfidence(source, findings),
    blockers,
    findings,
  };
}
