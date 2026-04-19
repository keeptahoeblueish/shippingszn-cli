import * as path from "node:path";
import { fileExists, readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";
import { relPosix } from "./helpers.js";

export async function checkEnvCommitted(ctx: CheckContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  const gitignorePath = path.join(ctx.rootDir, ".gitignore");
  let gitignore = "";
  if (await fileExists(gitignorePath)) {
    gitignore = (await readFileSafe({ absPath: gitignorePath, relPath: ".gitignore", size: 0 })) ?? "";
  }
  const ignoresEnv = /^\s*\.env(\s|$)/m.test(gitignore) || /^\s*\*\.env(\s|$)/m.test(gitignore);

  for (const file of ctx.files) {
    const base = path.basename(file.relPath);
    if (base !== ".env" && base !== ".env.local" && base !== ".env.production") continue;
    if (!ignoresEnv) {
      findings.push({
        checkId: "env-not-ignored",
        itemId: "secrets",
        severity: "high",
        message: `${base} found and your .gitignore does not appear to ignore .env files.`,
        file: relPosix(file.relPath),
      });
    }
  }
  return findings;
}

export async function checkEnvExample(ctx: CheckContext): Promise<Finding[]> {
  const hasEnv = ctx.files.some((f) => path.basename(f.relPath) === ".env");
  const hasExample = ctx.files.some((f) => {
    const b = path.basename(f.relPath);
    return b === ".env.example" || b === ".env.sample" || b === ".env.template";
  });
  if (hasEnv && !hasExample) {
    return [
      {
        checkId: "missing-env-example",
        itemId: "secrets",
        severity: "medium",
        message:
          "Found a .env file but no .env.example. Add a sanitized .env.example so collaborators know which variables are required.",
      },
    ];
  }
  return [];
}

export async function checkGitignore(ctx: CheckContext): Promise<Finding[]> {
  const gitignorePath = path.join(ctx.rootDir, ".gitignore");
  if (!(await fileExists(gitignorePath))) {
    return [
      {
        checkId: "missing-gitignore",
        itemId: "github",
        severity: "high",
        message:
          "No .gitignore at the project root. Add one tuned to your stack so you don't accidentally commit secrets, local DBs, or build artifacts.",
      },
    ];
  }
  return [];
}
