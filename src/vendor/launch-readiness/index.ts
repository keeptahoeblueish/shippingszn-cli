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

export interface FullChecklistEntry {
  id: string;
  title: string;
  priority: CanonicalSeverity;
  category: string;
  cliCoverage: "automated" | "manual_only";
  cliPrompt?: {
    whatFailed: string;
    whyItBlocksLaunch: string;
    fixInstructions: string;
    aiBuilderPrompt: string;
    verificationStep: string;
  };
  whyManual?: string;
  what?: string;
  why?: string;
  steps?: readonly string[];
  redFlags?: readonly string[];
  prompt?: string;
}

export interface VerifiedCleanEntry {
  id: string;
  title: string;
  priority: CanonicalSeverity;
  category: string;
}

export interface OwnerVerifyEntry {
  id: string;
  title: string;
  priority: CanonicalSeverity;
  category: string;
  what: string;
  why: string;
  steps: readonly string[];
  redFlags: readonly string[];
  prompt: string;
  whyManual: string;
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

export interface LaunchReportArtifact {
  version: 1;
  generatedAt: string;
  source: LaunchReadinessSource;
  targetName: string;
  targetUrl?: string;
  score: number;
  rawScore: number;
  label: string;
  decision: string;
  decisionLabel: string;
  goNoGoLabel: string;
  confidence: LaunchConfidence;
  counts: LaunchReadinessCounts;
  coveragePenalty: number;
  coverageSummary: string;
  coverage: LaunchCoverageArea[];
  proofBoundary: {
    proves: string[];
    limitations: string[];
  };
  nextAction: string;
  blockers: NormalizedLaunchFinding[];
  evidence: Array<{
    title: string;
    severity: CanonicalSeverity;
    evidence: string;
    confidence: LaunchConfidence;
  }>;
  fixes: Array<{
    title: string;
    severity: CanonicalSeverity;
    fixInstructions: string;
    aiBuilderPrompt: string;
    verificationStep: string;
  }>;
  verifiedClean?: VerifiedCleanEntry[];
  ownerVerify?: OwnerVerifyEntry[];
  markdown: string;
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

function scoreWithinBand(rawScore: number, band: ScoreBand): number {
  return Math.max(band.minScore, Math.min(band.maxScore, rawScore));
}

function severityBandedScore(
  rawScore: number,
  counts: LaunchReadinessCounts,
): number {
  if (counts.critical > 0) {
    return Math.min(rawScore, SCORE_BANDS[0]!.maxScore);
  }
  if (counts.high > 0) {
    return scoreWithinBand(rawScore, SCORE_BANDS[1]!);
  }
  if (counts.medium > 0) {
    return scoreWithinBand(rawScore, SCORE_BANDS[2]!);
  }
  if (counts.lower > 0) {
    return scoreWithinBand(rawScore, SCORE_BANDS[3]!);
  }
  return SCORE_BANDS[3]!.maxScore;
}

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

function sourceLabel(source: LaunchReadinessSource) {
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

function coverageForSource(
  source: LaunchReadinessSource,
): LaunchCoverageArea[] {
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
        "Secrets, committed env files, and config leaks require the CLI or GitHub Action.",
      ),
      coverageArea(
        "auth",
        "not_checked",
        "Private routes, role guards, OTP delivery, phone normalization, resend behavior, and recovery paths cannot be proven from a public unauthenticated fetch.",
      ),
      coverageArea(
        "paid_api",
        "not_checked",
        "Spend caps, rate limits, and provider abuse controls require repository or operator context.",
      ),
      coverageArea(
        "deployment",
        "partial",
        "HTTPS and response behavior were checked; runtime env and deploy config were not.",
      ),
      coverageArea(
        "content",
        "checked",
        "Public metadata, placeholder copy, and launch-page signals were checked.",
        "medium",
      ),
      coverageArea(
        "proof",
        "checked",
        "The result can be saved as proof and used to generate a report handoff.",
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
        "Repository signals were scanned; live production behavior still needs a URL scan.",
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
        "Static auth and OTP-risk signals were checked; runtime role behavior and real email/SMS delivery still need verification.",
      ),
      coverageArea(
        "paid_api",
        "partial",
        "Static paid-provider and limiter signals were checked; real spend caps still need owner verification.",
      ),
      coverageArea(
        "deployment",
        "partial",
        "Deploy-facing files and config signals were scanned; hosted environment settings may still be outside the repo.",
      ),
      coverageArea(
        "content",
        "checked",
        "Launch metadata, public assets, placeholder content, and checklist-backed file signals were scanned.",
      ),
      coverageArea(
        "proof",
        "checked",
        "The result can create proof, badge, Wall, and report handoff artifacts.",
      ),
    ];
  }

  return [
    coverageArea(
      "public_surface",
      "partial",
      "Manual intake may include public URL context, but no automated URL scan is guaranteed.",
      "low",
    ),
    coverageArea(
      "repo_static",
      "partial",
      "Manual evidence can describe repository risks, but the scanner has not verified them.",
      "low",
    ),
    coverageArea(
      "secrets",
      "partial",
      "Manual evidence can mention secrets; run the CLI or GitHub Action for proof.",
      "low",
    ),
    coverageArea(
      "auth",
      "partial",
      "Manual evidence can mention auth and OTP risk; runtime verification and delivered-code smoke are still required.",
      "low",
    ),
    coverageArea(
      "paid_api",
      "partial",
      "Manual evidence can mention paid API risk; provider-side spend controls are still unverified.",
      "low",
    ),
    coverageArea(
      "deployment",
      "partial",
      "Manual evidence can mention deployment risk; hosted settings are not automatically checked.",
      "low",
    ),
    coverageArea(
      "content",
      "partial",
      "Manual evidence can mention content polish; run a URL scan for public-page proof.",
      "low",
    ),
    coverageArea(
      "proof",
      "checked",
      "The result can still be packaged into a report handoff.",
      "low",
    ),
  ];
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

function defaultWhy(
  severity: CanonicalSeverity,
  source: LaunchReadinessSource,
) {
  if (severity === "critical") {
    return `This is treated as critical launch debt from the ${sourceLabel(source)} because it can expose users, secrets, revenue, or the primary launch surface.`;
  }
  if (severity === "high") {
    return `This can turn a launch into a trust, security, cost, or conversion problem even if the app appears to work.`;
  }
  if (severity === "medium") {
    return `This weakens launch readiness and should be fixed before public announcement, indexing, or paid traffic.`;
  }
  return `This is lower-priority readiness polish, but it still belongs in the fix queue before the launch proof is treated as clean.`;
}

function locationLine(finding: LaunchFindingInput) {
  if (finding.location?.trim()) return finding.location.trim();
  if (!finding.file?.trim()) return "";
  return finding.line
    ? `${finding.file.trim()}:${finding.line}`
    : finding.file.trim();
}

export interface FindingPromptInput {
  severity: CanonicalSeverity;
  title: string;
  whatFailed: string;
  whyItBlocksLaunch: string;
  fixInstructions: string;
  verificationStep: string;
  location?: string;
}

export type FindingPromptBuilder = (input: FindingPromptInput) => string;

export function normalizeLaunchFinding(
  finding: LaunchFindingInput,
  source: LaunchReadinessSource = "manual",
  promptBuilder?: FindingPromptBuilder,
): NormalizedLaunchFinding {
  const severity = canonicalSeverity(finding.severity);
  const title = clampText(
    finding.title ?? finding.itemTitle,
    "Launch-readiness finding",
    160,
  );
  const body = clampText(
    finding.body ?? finding.message,
    "The scan flagged this as a launch-readiness risk.",
    3000,
  );
  const whatFailed = clampText(finding.whatFailed, body, 3000);
  const whyItBlocksLaunch = clampText(
    finding.whyItBlocksLaunch,
    body || defaultWhy(severity, source),
    3000,
  );
  const fixInstructions = clampText(
    finding.fixInstructions ?? finding.fixPrompt,
    `Fix the underlying ${severity} launch-readiness risk and keep the app behavior intact.`,
    4000,
  );
  const verificationStep = clampText(
    finding.verificationStep ?? finding.verify,
    "Run the same scan again and confirm this finding is gone before launch.",
    3000,
  );
  const location = locationLine(finding);
  const aiBuilderPrompt = clampText(
    finding.aiBuilderPrompt,
    promptBuilder
      ? promptBuilder({
          severity,
          title,
          whatFailed,
          whyItBlocksLaunch,
          fixInstructions,
          verificationStep,
          location,
        })
      : "",
    4000,
  );
  const evidence = clampText(
    finding.evidence,
    location ? `Observed at ${location}.` : body,
    3000,
  );
  const confidence = normalizeConfidence(
    finding.confidence,
    confidenceForSource(source),
  );

  return {
    severity,
    title,
    whatFailed,
    whyItBlocksLaunch,
    fixInstructions,
    aiBuilderPrompt,
    verificationStep,
    evidence,
    confidence,
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
  promptBuilder?: FindingPromptBuilder,
): NormalizedLaunchFinding[] {
  return findings
    .map((finding) => normalizeLaunchFinding(finding, source, promptBuilder))
    .sort((a, b) => {
      const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
      if (bySeverity !== 0) return bySeverity;
      return a.title.localeCompare(b.title);
    });
}

function scoreFromCounts(
  counts: LaunchReadinessCounts,
  source: LaunchReadinessSource,
): {
  score: number;
  rawScore: number;
  weightedPenalty: number;
  coveragePenalty: number;
} {
  const weightedPenalty =
    counts.critical * SEVERITY_WEIGHTS.critical +
    counts.high * SEVERITY_WEIGHTS.high +
    counts.medium * SEVERITY_WEIGHTS.medium +
    counts.lower * SEVERITY_WEIGHTS.lower;
  const rawScore = clampScore(100 - weightedPenalty);
  const severityScore = severityBandedScore(rawScore, counts);
  const scoreCap = SOURCE_SCORE_CAP[source];
  const score = Math.min(severityScore, scoreCap);
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
) {
  if (counts.critical > 0) {
    return `Fix now. ${counts.critical} critical finding${counts.critical === 1 ? "" : "s"} should be fixed and rescanned before more public traffic.`;
  }
  if (counts.high > 0) {
    return `Fix the high-risk launch gaps before a real campaign, customer demo, or paid traffic.`;
  }
  if (counts.medium > 0 || counts.lower > 0) {
    return `No critical or high finding was detected, but the remaining readiness gaps should be fixed and verified before treating the ${sourceLabel(source)} as day-1 ready.`;
  }
  if (source === "url") {
    return "No public-page critical findings were found. Run the CLI or GitHub Action before calling the app day-1 ready.";
  }
  return `${band.goNoGoLabel}: no scan-detected critical findings were found. Monitor first production traffic.`;
}

function topNextStep(
  blockers: readonly NormalizedLaunchFinding[],
  counts: LaunchReadinessCounts,
  source: LaunchReadinessSource,
) {
  const top = blockers[0];
  if (top) {
    return `Fix ${top.title}: ${top.whatFailed}`;
  }
  if (source === "url") {
    return "Run the repo scan next so secrets, auth, API routes, and generated-code risks are checked before launch.";
  }
  if (counts.medium > 0 || counts.lower > 0) {
    return "Fix the remaining readiness gaps and rescan before the next launch push.";
  }
  return "No obvious critical launch debt caught. Monitor first production traffic and keep the paid report for higher-stakes launches.";
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
  promptBuilder?: FindingPromptBuilder,
): LaunchReadinessAssessment {
  const source = input.source ?? "manual";
  const findings = prioritizeLaunchFindings(
    input.findings ?? [],
    source,
    promptBuilder,
  );
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
  const decision = decisionText(band, counts, source);
  const reportRecommended =
    counts.critical > 0 || counts.high > 0 || coveragePenalty > 0;

  return {
    score,
    rawScore,
    label: band.label,
    decision,
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
    topNextStep: topNextStep(
      blockers.length ? blockers : findings,
      counts,
      source,
    ),
    reportRecommended,
    confidence: aggregateConfidence(source, findings),
    blockers,
    findings,
  };
}

function proofBoundaryForReport(
  report: Pick<
    LaunchReportArtifact,
    "source" | "targetName" | "score" | "label" | "coverageSummary"
  >,
) {
  return {
    proves: [
      `${sourceLabel(report.source)} evidence was turned into a shippingszn launch-readiness score for ${report.targetName}.`,
      `The report, proof page, and badge can point at the same stored scan evidence and severity counts.`,
      `A ${report.score}/100 ${report.label} result reflects the findings present when the scan was created.`,
    ],
    limitations: [
      "This is not a formal security audit, penetration test, compliance certification, or provider delivery guarantee.",
      report.source === "url"
        ? "A public URL scan cannot prove repository secrets, private auth routes, OTP delivery, role guards, or paid API spend controls."
        : "A repository scan cannot prove production-only environment settings, live user permissions, or real email/SMS delivery by itself.",
      "If paid report access depends on email/SMS OTP, verify a real delivered code in the target environment before production approval.",
      `Scope boundary: ${report.coverageSummary}`,
    ],
  };
}

function checklistItemIdFromFinding(finding: LaunchFindingInput) {
  if (finding.itemId) return finding.itemId;
  if (!finding.permalink) return undefined;
  const ITEM_PATH = /\/i\/([^/?#]+)/;
  // RegExp.prototype.exec — when this matches, capture group 1 is always
  // populated. `?.[1] !== undefined` exists only to satisfy TS under the
  // noUncheckedIndexedAccess flag.
  const captureFromPath = (input: string): string | undefined => {
    const match = ITEM_PATH.exec(input);
    const captured = match?.[1];
    return captured !== undefined ? decodeURIComponent(captured) : undefined;
  };
  try {
    return captureFromPath(new URL(finding.permalink).pathname);
  } catch {
    return captureFromPath(finding.permalink);
  }
}

function needsChecklistWhy(
  value: string | undefined,
  finding: LaunchFindingInput,
) {
  const trimmed = value?.trim();
  if (!trimmed) return true;
  const body = (finding.body ?? finding.message ?? "").trim();
  return Boolean(body && trimmed === body);
}

function needsChecklistFix(value: string | undefined) {
  const trimmed = value?.trim() ?? "";
  return (
    !trimmed ||
    /^Fix the underlying [a-z]+ launch-readiness risk/i.test(trimmed)
  );
}

function needsChecklistVerification(value: string | undefined) {
  const trimmed = value?.trim() ?? "";
  return (
    !trimmed ||
    /^Run the same scan again and confirm this finding is gone/i.test(trimmed)
  );
}

function needsChecklistPrompt(value: string | undefined) {
  const trimmed = value?.trim() ?? "";
  return (
    !trimmed ||
    ((trimmed.includes(
      "You are fixing a shippingszn launch-readiness finding",
    ) ||
      trimmed.includes(
        "You are fixing a shippingszn launch-readiness blocker",
      )) &&
      trimmed.includes("Fix the underlying"))
  );
}

function checklistFixInstructions(item: FullChecklistEntry) {
  if (item.steps && item.steps.length > 0) {
    return item.steps.join(" ");
  }
  if (item.prompt?.trim()) return item.prompt.trim();
  return `Fix ${item.title} in the smallest production-safe way, then rerun the launch-readiness scan.`;
}

function checklistVerificationStep(item: FullChecklistEntry) {
  const base = `Re-run npx shippingszn --proof and confirm the ${item.title} finding is gone before launch.`;
  if (item.cliCoverage === "manual_only") return base;
  return `${base} Also run the app's normal typecheck/test/build command when the fix changes code, config, routing, security behavior, or public assets.`;
}

function checklistAiBuilderPrompt(
  item: FullChecklistEntry,
  finding: LaunchFindingInput,
  sourcePrompt?: string,
) {
  const evidence = finding.evidence?.trim()
    ? `Evidence from scan: ${finding.evidence.trim()}`
    : "Use the scanner message and relevant source files as evidence.";
  const location = locationLine(finding);
  return [
    "You are my senior launch-readiness engineer working inside this codebase.",
    `Fix the checklist area: ${item.title}.`,
    `Scanner finding: ${finding.title ?? finding.itemTitle ?? item.title}.`,
    finding.body || finding.message
      ? `Scanner message: ${finding.body ?? finding.message}.`
      : "",
    evidence,
    location ? `Likely location: ${location}.` : "",
    "Use this checklist prompt as the source task:",
    sourcePrompt?.trim() ||
      item.prompt?.trim() ||
      checklistFixInstructions(item),
    "Make the smallest production-safe change that removes the underlying issue and preserves existing behavior.",
    "List every file changed, explain why each change was needed, and do not suppress the scanner unless you can prove a false positive.",
    checklistVerificationStep(item),
  ]
    .filter(Boolean)
    .join(" ");
}

function hydrateFindingFromChecklist(
  finding: LaunchFindingInput,
  checklistById: Map<string, FullChecklistEntry>,
): LaunchFindingInput {
  const itemId = checklistItemIdFromFinding(finding);
  if (!itemId) return finding;
  const item = checklistById.get(itemId);
  if (!item) return finding;
  const cliPrompt = item.cliPrompt;

  return {
    ...finding,
    itemId,
    itemTitle: finding.itemTitle ?? item.title,
    title: finding.title ?? item.title,
    whatFailed:
      finding.whatFailed?.trim() ||
      cliPrompt?.whatFailed ||
      finding.body ||
      finding.message ||
      `The scan mapped this issue to ${item.title}.`,
    whyItBlocksLaunch: needsChecklistWhy(finding.whyItBlocksLaunch, finding)
      ? cliPrompt?.whyItBlocksLaunch || item.why
      : finding.whyItBlocksLaunch,
    fixInstructions: needsChecklistFix(
      finding.fixInstructions ?? finding.fixPrompt,
    )
      ? cliPrompt?.fixInstructions || checklistFixInstructions(item)
      : (finding.fixInstructions ?? finding.fixPrompt),
    verificationStep: needsChecklistVerification(
      finding.verificationStep ?? finding.verify,
    )
      ? [cliPrompt?.verificationStep, checklistVerificationStep(item)]
          .filter(Boolean)
          .join(" ")
      : (finding.verificationStep ?? finding.verify),
    aiBuilderPrompt: needsChecklistPrompt(finding.aiBuilderPrompt)
      ? checklistAiBuilderPrompt(item, finding, cliPrompt?.aiBuilderPrompt)
      : finding.aiBuilderPrompt,
  };
}

const CLI_VERIFIED_AUTOMATED_ITEM_IDS = new Set([
  "secrets",
  "common-attacks",
  "https-headers",
  "dev-prod-data",
  "secure-auth",
  "api-spend-cap",
  "rate-limiting",
  "error-monitoring",
  "legal-pages",
  "payments",
  "file-uploads",
  "session-management",
  "secure-api",
  "github",
  "seo",
  "launch-polish",
  "ai-audit",
  "aeo",
  "installable-app",
  "model-freshness",
  "dependency-integrity",
]);

const URL_VERIFIED_AUTOMATED_ITEM_IDS = new Set([
  "https-headers",
  "seo",
  "launch-polish",
  "ai-audit",
]);

function verifiedAutomatedItemIdsForSource(source: LaunchReadinessSource) {
  if (source === "cli" || source === "github") {
    return CLI_VERIFIED_AUTOMATED_ITEM_IDS;
  }
  if (source === "url") return URL_VERIFIED_AUTOMATED_ITEM_IDS;
  return new Set<string>();
}

function sourceGapReason(source: LaunchReadinessSource) {
  if (source === "url") {
    return "Owner or repo verification required because the live URL scan cannot inspect source files, secrets, auth code, GitHub hygiene, or project configuration.";
  }
  if (source === "manual") {
    return "Owner verification required because this report was not generated from an automated repo or URL scan for this checklist item.";
  }
  return "Owner verification required because this item cannot be proven from static scan signals.";
}

function fullChecklistCoverage(input: {
  source: LaunchReadinessSource;
  fullChecklist?: readonly FullChecklistEntry[];
  findings?: readonly LaunchFindingInput[];
}): {
  verifiedClean?: VerifiedCleanEntry[];
  ownerVerify?: OwnerVerifyEntry[];
} {
  if (!input.fullChecklist) return {};

  const flaggedItemIds = new Set(
    (input.findings ?? [])
      .map((finding) => checklistItemIdFromFinding(finding))
      .filter((id): id is string => Boolean(id)),
  );

  const verifiedClean: VerifiedCleanEntry[] = [];
  const ownerVerify: OwnerVerifyEntry[] = [];
  const verifiedAutomatedItemIds = verifiedAutomatedItemIdsForSource(
    input.source,
  );

  for (const item of input.fullChecklist) {
    if (item.cliCoverage === "automated") {
      if (
        !flaggedItemIds.has(item.id) &&
        verifiedAutomatedItemIds.has(item.id)
      ) {
        verifiedClean.push({
          id: item.id,
          title: item.title,
          priority: item.priority,
          category: item.category,
        });
      } else if (!flaggedItemIds.has(item.id)) {
        ownerVerify.push({
          id: item.id,
          title: item.title,
          priority: item.priority,
          category: item.category,
          what: item.what ?? "",
          why: item.why ?? "",
          steps: item.steps ?? [],
          redFlags: item.redFlags ?? [],
          prompt: item.prompt ?? "",
          whyManual: sourceGapReason(input.source),
        });
      }
      continue;
    }

    ownerVerify.push({
      id: item.id,
      title: item.title,
      priority: item.priority,
      category: item.category,
      what: item.what ?? "",
      why: item.why ?? "",
      steps: item.steps ?? [],
      redFlags: item.redFlags ?? [],
      prompt: item.prompt ?? "",
      whyManual:
        item.whyManual ??
        "Owner verification required because this item cannot be proven from static scan signals.",
    });
  }

  return { verifiedClean, ownerVerify };
}

function reportMarkdown(report: Omit<LaunchReportArtifact, "markdown">) {
  const aiPunchList = buildAiPunchListMarkdown(report);
  const lines = [
    "# Launch Readiness Report",
    "",
    `Target: ${report.targetName}`,
    `Score: ${report.score}/100`,
    report.coveragePenalty > 0
      ? `Raw severity score: ${report.rawScore}/100; coverage cap applied: -${report.coveragePenalty}`
      : `Raw severity score: ${report.rawScore}/100`,
    `Decision: ${report.goNoGoLabel} - ${report.label}`,
    `Confidence: ${report.confidence}`,
    `Scope: ${report.coverageSummary}`,
    "",
    "## Scope Checked",
    "",
    ...report.coverage.map(
      (area) =>
        `- ${area.status.toUpperCase()}: ${area.label} - ${area.evidence}`,
    ),
    "",
    "## Proof Boundary",
    "",
    "What this proves:",
    "",
    ...report.proofBoundary.proves.map((item) => `- ${item}`),
    "",
    "What this does not prove:",
    "",
    ...report.proofBoundary.limitations.map((item) => `- ${item}`),
    "",
    ...aiPunchList,
    "",
    "## Findings and Remediation",
  ];

  if (report.blockers.length === 0) {
    lines.push("", "No scanner findings were detected.");
  } else {
    for (const blocker of report.blockers) {
      lines.push(
        "",
        `### ${blocker.severity.toUpperCase()}: ${blocker.title}`,
        "",
        `What failed: ${blocker.whatFailed}`,
        "",
        `Why it matters now: ${blocker.whyItBlocksLaunch}`,
        "",
        `Evidence: ${blocker.evidence}`,
        "",
        `Fix: ${blocker.fixInstructions}`,
        "",
        `AI-builder prompt: ${blocker.aiBuilderPrompt}`,
        "",
        `Verify: ${blocker.verificationStep}`,
      );
    }
  }

  if (report.verifiedClean && report.verifiedClean.length > 0) {
    lines.push(
      "",
      "## Verified Clean",
      "",
      "_Items this scan source checked and passed. No action needed._",
      "",
    );
    for (const item of report.verifiedClean) {
      lines.push(`- ${item.title} (${item.priority})`);
    }
  }

  if (report.ownerVerify && report.ownerVerify.length > 0) {
    lines.push(
      "",
      "## Owner Verification Required",
      "",
      "_Items the scanner cannot prove from static signals. Confirm each one against the live app or your records._",
    );
    for (const item of report.ownerVerify) {
      lines.push(
        "",
        `### ${item.title} (${item.priority})`,
        "",
        `**Why the scanner can't prove this:** ${item.whyManual}`,
        "",
        `**What:** ${item.what}`,
        "",
        `**Why:** ${item.why}`,
        "",
        "**Steps:**",
      );
      for (const step of item.steps) lines.push(`1. ${step}`);
      lines.push("", "**Red flags:**");
      for (const flag of item.redFlags) lines.push(`- ${flag}`);
      lines.push(
        "",
        "**Verify with this AI prompt:**",
        "",
        "```",
        item.prompt,
        "```",
      );
    }
  }

  lines.push("", "## Next Action", "", report.nextAction);
  return lines.join("\n");
}

function pushMarkdownLine(
  lines: string[],
  label: string,
  value?: string | null,
) {
  const text = value?.trim();
  if (!text) return;
  lines.push(`- ${label}: ${text}`);
}

function buildAiPunchListMarkdown(
  report: Omit<LaunchReportArtifact, "markdown">,
) {
  const lines = [
    "## For my AI",
    "",
    `Target: ${report.targetName}`,
    `Decision: ${report.goNoGoLabel} - ${report.label}`,
    `Score: ${report.score}/100`,
    "",
    "You are the AI builder fixing this app before launch. Do not claim a fix is complete unless you changed the relevant files and ran the verification step. If a task needs credentials, production access, legal judgment, provider-dashboard action, or founder approval, stop and ask for that approval instead of guessing.",
    "",
    "## Scanner tasks",
    "",
  ];

  if (report.blockers.length === 0) {
    lines.push("No scanner findings are open in this report.", "");
  }

  report.blockers.forEach((finding, index) => {
    const taskId = `AI-${String(index + 1).padStart(3, "0")}`;
    lines.push(`### ${taskId} - ${finding.title}`);
    pushMarkdownLine(lines, "Severity", finding.severity);
    pushMarkdownLine(lines, "Checklist control", finding.itemTitle);
    pushMarkdownLine(lines, "Location", finding.location);
    pushMarkdownLine(lines, "Evidence", finding.evidence);
    pushMarkdownLine(lines, "What failed", finding.whatFailed || finding.body);
    pushMarkdownLine(lines, "Why it blocks launch", finding.whyItBlocksLaunch);
    lines.push(
      "- Owner approval flag: human review required before ship signoff",
      "",
      "Prompt for AI builder:",
      "```",
      finding.aiBuilderPrompt ||
        finding.fixPrompt ||
        finding.fixInstructions ||
        `Inspect and fix this shippingszn launch finding: ${finding.title}`,
      "```",
      "",
      "Verification:",
      finding.verificationStep ||
        finding.verify ||
        "Rerun npx shippingszn@latest and confirm this finding is gone.",
      "",
    );
  });

  lines.push("## Owner approval required", "");

  const ownerVerify = report.ownerVerify ?? [];
  if (ownerVerify.length === 0) {
    lines.push("No owner-only controls are attached to this report.", "");
  }

  ownerVerify.forEach((item, index) => {
    const taskId = `OWNER-${String(index + 1).padStart(3, "0")}`;
    lines.push(`### ${taskId} - ${item.title}`);
    pushMarkdownLine(lines, "Priority", item.priority);
    pushMarkdownLine(lines, "Category", item.category);
    pushMarkdownLine(lines, "Why scanner cannot prove it", item.whyManual);
    lines.push(
      "- Owner approval flag: owner approval required before ship signoff",
    );
    if (item.steps.length > 0) {
      lines.push("", "Owner verification steps:");
      item.steps.forEach((step, stepIndex) => {
        lines.push(`${stepIndex + 1}. ${step}`);
      });
    }
    if (item.prompt.trim()) {
      lines.push("", "Prompt for AI builder:", "```", item.prompt, "```");
    }
    lines.push("");
  });

  lines.push(
    "Final instruction: after the AI builder claims completion, rerun `npx shippingszn@latest` from the project root and compare the new score, severity counts, and remaining owner approvals before shipping.",
  );

  return lines;
}

export function generateLaunchReportArtifact(
  input: {
    source?: LaunchReadinessSource;
    targetName?: string | null;
    targetUrl?: string | null;
    checkedAt?: string;
    findings?: LaunchFindingInput[];
    counts?: Partial<Record<CanonicalSeverity, number>>;
    fullChecklist?: readonly FullChecklistEntry[];
  },
  promptBuilder?: FindingPromptBuilder,
): LaunchReportArtifact {
  const source = input.source ?? "manual";
  const checklistById = new Map(
    (input.fullChecklist ?? []).map((item) => [item.id, item]),
  );
  const reportFindings =
    input.fullChecklist && input.findings
      ? input.findings.map((finding) =>
          hydrateFindingFromChecklist(finding, checklistById),
        )
      : input.findings;
  const assessment = assessLaunchReadiness(
    {
      source,
      findings: reportFindings,
      counts: input.counts,
      targetName: input.targetName,
      targetUrl: input.targetUrl,
      checkedAt: input.checkedAt,
    },
    promptBuilder,
  );
  const blockers = assessment.findings;
  const targetName =
    input.targetName?.trim() || input.targetUrl?.trim() || "AI-built app";
  const { verifiedClean, ownerVerify } = fullChecklistCoverage({
    source,
    fullChecklist: input.fullChecklist,
    findings: reportFindings,
  });
  const artifactWithoutMarkdown = {
    version: 1 as const,
    generatedAt: new Date().toISOString(),
    source,
    targetName,
    ...(input.targetUrl ? { targetUrl: input.targetUrl } : {}),
    score: assessment.score,
    rawScore: assessment.rawScore,
    label: assessment.label,
    decision: assessment.decision,
    decisionLabel: assessment.decisionLabel,
    goNoGoLabel: assessment.goNoGoLabel,
    confidence: assessment.confidence,
    counts: assessment.counts,
    coveragePenalty: assessment.coveragePenalty,
    coverageSummary: assessment.coverageSummary,
    coverage: assessment.coverage,
    proofBoundary: proofBoundaryForReport({
      source,
      targetName,
      score: assessment.score,
      label: assessment.label,
      coverageSummary: assessment.coverageSummary,
    }),
    nextAction: assessment.topNextStep,
    blockers,
    evidence: blockers.map((finding) => ({
      title: finding.title,
      severity: finding.severity,
      evidence: finding.evidence,
      confidence: finding.confidence,
    })),
    fixes: blockers.map((finding) => ({
      title: finding.title,
      severity: finding.severity,
      fixInstructions: finding.fixInstructions,
      aiBuilderPrompt: finding.aiBuilderPrompt,
      verificationStep: finding.verificationStep,
    })),
    ...(verifiedClean ? { verifiedClean } : {}),
    ...(ownerVerify ? { ownerVerify } : {}),
  };

  return {
    ...artifactWithoutMarkdown,
    markdown: reportMarkdown(artifactWithoutMarkdown),
  };
}
