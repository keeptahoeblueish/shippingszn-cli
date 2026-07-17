import {
  assessLaunchReadiness as coreAssessLaunchReadiness,
  generateLaunchReportArtifact as coreGenerateLaunchReportArtifact,
  normalizeLaunchFinding as coreNormalizeLaunchFinding,
  prioritizeLaunchFindings as corePrioritizeLaunchFindings,
} from "./index.js";
import { defaultPrompt } from "./server-prompts.js";

export * from "./index.js";
export { defaultPrompt } from "./server-prompts.js";

export const normalizeLaunchFinding: typeof coreNormalizeLaunchFinding = (
  finding,
  source,
  promptBuilder,
) => coreNormalizeLaunchFinding(finding, source, promptBuilder ?? defaultPrompt);

export const prioritizeLaunchFindings: typeof corePrioritizeLaunchFindings = (
  findings,
  source,
  promptBuilder,
) =>
  corePrioritizeLaunchFindings(findings, source, promptBuilder ?? defaultPrompt);

export const assessLaunchReadiness: typeof coreAssessLaunchReadiness = (
  input,
  promptBuilder,
) => coreAssessLaunchReadiness(input, promptBuilder ?? defaultPrompt);

export const generateLaunchReportArtifact: typeof coreGenerateLaunchReportArtifact =
  (input, promptBuilder) =>
    coreGenerateLaunchReportArtifact(input, promptBuilder ?? defaultPrompt);
