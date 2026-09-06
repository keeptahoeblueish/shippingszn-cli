import { createInterface } from "node:readline/promises";
import { stdin, stderr, stdout } from "node:process";
import { configuredEngines, keyEnvName, VISIBILITY_LIMITS } from "./config.js";
import { redactSecrets } from "./redaction.js";
import { writeVisibilityReport } from "./report.js";
import { runLocalVisibilityScan } from "./run.js";
import {
  VISIBILITY_ENGINES,
  type VisibilityEngine,
} from "./types.js";

interface VisibilityCommandOptions {
  url: string;
  engines: VisibilityEngine[];
  yes: boolean;
  output: string;
}

function parseEngines(value: string): VisibilityEngine[] {
  const engines = value.split(",").map((item) => item.trim().toLowerCase());
  if (
    engines.length === 0 ||
    engines.some((engine) => !VISIBILITY_ENGINES.includes(engine as VisibilityEngine))
  ) {
    throw new Error(`--engines must use: ${VISIBILITY_ENGINES.join(",")}`);
  }
  return engines as VisibilityEngine[];
}

function parseVisibilityArgs(args: string[]): VisibilityCommandOptions {
  const url = args[0];
  if (!url || url.startsWith("-")) {
    throw new Error("Usage: shippingszn visibility <url> [--engines openai,anthropic] [--yes] [--output path]");
  }
  new URL(url);
  const options: VisibilityCommandOptions = {
    url,
    engines: [...VISIBILITY_ENGINES],
    yes: false,
    output: "shippingszn-visibility",
  };
  for (let index = 1; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--yes") options.yes = true;
    else if (arg === "--engines") {
      const value = args[++index];
      if (!value) throw new Error("--engines requires a value");
      options.engines = parseEngines(value);
    } else if (arg === "--output") {
      const value = args[++index];
      if (!value) throw new Error("--output requires a value");
      options.output = value;
    } else if (arg?.includes("key") || arg?.includes("token")) {
      throw new Error("Provider credentials must use environment variables, never CLI flags.");
    } else {
      throw new Error(`Unknown visibility option: ${arg}`);
    }
  }
  return options;
}

function defaultPrompts(url: string): string[] {
  const host = new URL(url).hostname.replace(/^www\./, "");
  return [
    `What does ${host} offer?`,
    `Who should use ${host}?`,
    `What are the best alternatives to ${host}?`,
    `Is ${host} trustworthy?`,
    `Which products compete with ${host}?`,
  ];
}

async function confirmSpend(): Promise<boolean> {
  if (!stdin.isTTY) return false;
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    const answer = await rl.question("Run these provider calls? [y/N] ");
    return answer.trim().toLowerCase() === "y";
  } finally {
    rl.close();
  }
}

export async function runVisibilityCommand(args: string[]): Promise<number> {
  try {
    const options = parseVisibilityArgs(args);
    const coverage = configuredEngines(options.engines);
    const prompts = defaultPrompts(options.url);
    stderr.write("\nShippingSZN local BYOK visibility preflight\n");
    stderr.write(`Target: ${options.url}\n`);
    stderr.write(`Selected engines: ${options.engines.join(", ")}\n`);
    stderr.write(`Configured: ${coverage.configured.join(", ") || "none"}\n`);
    stderr.write(
      `Missing: ${coverage.missing.map((engine) => keyEnvName(engine)).join(", ") || "none"}\n`,
    );
    stderr.write(`Prompts per engine: ${prompts.length}\n`);
    stderr.write(
      `Maximum answer calls: ${Math.min(options.engines.length * prompts.length, VISIBILITY_LIMITS.maxAnswerCalls)}\n`,
    );
    stderr.write("Your provider account may be charged.\n\n");
    const confirmed = options.yes || (await confirmSpend());
    if (!confirmed) {
      stderr.write("No provider calls made. Use --yes for non-interactive execution.\n");
      return 2;
    }
    const report = await runLocalVisibilityScan({
      url: options.url,
      engines: options.engines,
      prompts,
      confirmed,
    });
    const paths = await writeVisibilityReport(report, options.output);
    stdout.write(`Visibility report written locally:\n${paths.jsonPath}\n${paths.markdownPath}\n`);
    return 0;
  } catch (error) {
    const message = redactSecrets(error instanceof Error ? error.message : String(error));
    stderr.write(`Visibility scan stopped: ${message}\n`);
    return 2;
  }
}
