import type { CanonicalSeverity } from "./index.js";

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

export const defaultPrompt: FindingPromptBuilder = (input) => {
  const where = input.location
    ? `Likely location: ${input.location}.`
    : "Inspect the relevant app, deploy, and configuration files before editing.";
  return [
    "You are fixing a shippingszn launch-readiness finding in an AI-built app.",
    `Severity: ${input.severity}.`,
    `Finding: ${input.title}.`,
    `What failed: ${input.whatFailed}`,
    `Why it matters now: ${input.whyItBlocksLaunch}`,
    where,
    `Fix exactly this: ${input.fixInstructions}`,
    `Verification required: ${input.verificationStep}`,
    "Make the smallest production-safe change, preserve existing behavior, list files changed, and do not suppress the scanner unless you prove a false positive.",
  ].join(" ");
};
