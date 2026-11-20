import type { VisibilityEngine } from "./types.js";

export const VISIBILITY_LIMITS = {
  maxEngines: 3,
  maxPromptsPerEngine: 5,
  maxAnswerCalls: 15,
  maxConcurrency: 2,
  maxTransientRetries: 1,
  requestTimeoutMs: 45_000,
} as const;

const KEY_ENV: Record<VisibilityEngine, string> = {
  openai: "OPENAI_API_KEY",
  anthropic: "ANTHROPIC_API_KEY",
};

export function keyEnvName(engine: VisibilityEngine): string {
  return KEY_ENV[engine];
}

export function configuredEngines(
  engines: VisibilityEngine[],
  env: NodeJS.ProcessEnv = process.env,
): { configured: VisibilityEngine[]; missing: VisibilityEngine[] } {
  const configured: VisibilityEngine[] = [];
  const missing: VisibilityEngine[] = [];
  for (const engine of engines) {
    if (env[KEY_ENV[engine]]?.trim()) configured.push(engine);
    else missing.push(engine);
  }
  return { configured, missing };
}

export function providerKey(
  engine: VisibilityEngine,
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  return env[KEY_ENV[engine]]?.trim() || null;
}
