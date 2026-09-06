import {
  configuredEngines,
  VISIBILITY_LIMITS,
} from "./config.js";
import { createAnthropicProvider } from "./providers/anthropic.js";
import { createOpenAIProvider } from "./providers/openai.js";
import { ProviderHttpError } from "./providers/shared.js";
import type {
  LocalVisibilityInput,
  LocalVisibilityReport,
  VisibilityAnswer,
  VisibilityEngine,
  VisibilityProvider,
} from "./types.js";

export interface VisibilityDependencies {
  env?: NodeJS.ProcessEnv;
  providers?: Partial<Record<VisibilityEngine, VisibilityProvider>>;
  now?: () => Date;
}

function validateInput(input: LocalVisibilityInput): void {
  if (!input.confirmed) throw new Error("Visibility provider spending was not confirmed.");
  if (input.engines.length === 0) throw new Error("Select at least one visibility engine.");
  if (new Set(input.engines).size !== input.engines.length) {
    throw new Error("Visibility engines must be unique.");
  }
  if (input.engines.length > VISIBILITY_LIMITS.maxEngines) {
    throw new Error(`At most ${VISIBILITY_LIMITS.maxEngines} engines are allowed.`);
  }
  if (input.prompts.length === 0) throw new Error("At least one prompt is required.");
  if (input.prompts.length > VISIBILITY_LIMITS.maxPromptsPerEngine) {
    throw new Error(
      `At most ${VISIBILITY_LIMITS.maxPromptsPerEngine} prompts per engine are allowed.`,
    );
  }
  if (input.engines.length * input.prompts.length > VISIBILITY_LIMITS.maxAnswerCalls) {
    throw new Error(`At most ${VISIBILITY_LIMITS.maxAnswerCalls} provider calls are allowed.`);
  }
}

async function callWithRetry(
  provider: VisibilityProvider,
  prompt: string,
): Promise<VisibilityAnswer> {
  for (let attempt = 0; attempt <= VISIBILITY_LIMITS.maxTransientRetries; attempt++) {
    try {
      return await provider.call(
        prompt,
        AbortSignal.timeout(VISIBILITY_LIMITS.requestTimeoutMs),
      );
    } catch (error) {
      const transient =
        error instanceof ProviderHttpError &&
        (error.status === 429 || error.status >= 500);
      if (!transient || attempt === VISIBILITY_LIMITS.maxTransientRetries) throw error;
    }
  }
  throw new Error("Provider retry limit reached.");
}

export async function runLocalVisibilityScan(
  input: LocalVisibilityInput,
  deps: VisibilityDependencies = {},
): Promise<LocalVisibilityReport> {
  validateInput(input);
  new URL(input.url);
  const env = deps.env ?? process.env;
  const coverage = configuredEngines(input.engines, env);
  if (coverage.configured.length === 0) {
    throw new Error("No selected visibility provider is configured.");
  }
  const providers: Record<VisibilityEngine, VisibilityProvider> = {
    openai: deps.providers?.openai ?? createOpenAIProvider(env),
    anthropic: deps.providers?.anthropic ?? createAnthropicProvider(env),
  };
  const jobs = coverage.configured.flatMap((engine) =>
    input.prompts.map((prompt) => ({ provider: providers[engine], prompt })),
  );
  const answers: VisibilityAnswer[] = [];
  let cursor = 0;
  const worker = async () => {
    while (cursor < jobs.length) {
      const job = jobs[cursor++];
      if (!job) return;
      answers.push(await callWithRetry(job.provider, job.prompt));
    }
  };
  await Promise.all(
    Array.from(
      { length: Math.min(VISIBILITY_LIMITS.maxConcurrency, jobs.length) },
      () => worker(),
    ),
  );
  answers.sort(
    (a, b) =>
      input.engines.indexOf(a.engine) - input.engines.indexOf(b.engine) ||
      input.prompts.indexOf(a.prompt) - input.prompts.indexOf(b.prompt),
  );
  return {
    schemaVersion: 1,
    executionMode: "local_byok",
    targetUrl: input.url,
    enginesRequested: input.engines,
    enginesCompleted: coverage.configured,
    enginesMissing: coverage.missing,
    answers,
    generatedAt: (deps.now?.() ?? new Date()).toISOString(),
  };
}
