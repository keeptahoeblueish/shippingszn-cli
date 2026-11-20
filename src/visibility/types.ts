export const VISIBILITY_ENGINES = ["openai", "anthropic"] as const;
export type VisibilityEngine = (typeof VISIBILITY_ENGINES)[number];

export interface LocalVisibilityInput {
  url: string;
  engines: VisibilityEngine[];
  prompts: string[];
  confirmed: boolean;
}

export interface VisibilityAnswer {
  engine: VisibilityEngine;
  prompt: string;
  text: string;
  citations: Array<{ title?: string; url: string }>;
}

export interface LocalVisibilityReport {
  schemaVersion: 1;
  executionMode: "local_byok";
  targetUrl: string;
  enginesRequested: VisibilityEngine[];
  enginesCompleted: VisibilityEngine[];
  enginesMissing: VisibilityEngine[];
  answers: VisibilityAnswer[];
  generatedAt: string;
}

export interface VisibilityProvider {
  readonly engine: VisibilityEngine;
  call(prompt: string, signal: AbortSignal): Promise<VisibilityAnswer>;
}
