import * as path from "node:path";
import { readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";
import { relPosix } from "./helpers.js";
import { makeFinding } from "./make-finding.js";

/**
 * "Slopsquatting": AI code generators routinely invent or misspell package
 * names, and attackers pre-register the ones models hallucinate consistently.
 * A CVE/SCA scan can't catch these — a freshly-registered malicious package has
 * no vulnerability history. This check flags dependency names that are a
 * near-miss (one edit or adjacent transposition) of a well-known package, which
 * is the classic typosquat shape, so the owner verifies the package is real
 * before trusting it.
 *
 * The offline popular-package list is intentionally conservative (length >= 5,
 * distance <= 1) to keep false positives low; it is a nudge to verify, not an
 * accusation. It is not exhaustive registry validation — the CLI is offline by
 * design, so it cannot confirm a package exists.
 */
const POPULAR_PACKAGES: readonly string[] = [
  "react",
  "react-dom",
  "react-router-dom",
  "next",
  "svelte",
  "express",
  "fastify",
  "lodash",
  "axios",
  "chalk",
  "commander",
  "dotenv",
  "typescript",
  "webpack",
  "eslint",
  "prettier",
  "vitest",
  "playwright",
  "tailwindcss",
  "postcss",
  "autoprefixer",
  "classnames",
  "nanoid",
  "dayjs",
  "moment",
  "date-fns",
  "helmet",
  "body-parser",
  "cookie-parser",
  "jsonwebtoken",
  "bcrypt",
  "bcryptjs",
  "mysql2",
  "mongoose",
  "ioredis",
  "drizzle-orm",
  "stripe",
  "twilio",
  "resend",
  "nodemailer",
  "openai",
  "langchain",
  "socket.io",
  "node-fetch",
  "undici",
  "puppeteer",
  "cheerio",
  "multer",
  "formidable",
  "passport",
  "winston",
  "morgan",
  "rimraf",
  "fs-extra",
  "yargs",
  "inquirer",
  "semver",
  "husky",
  "lint-staged",
  "concurrently",
  "nodemon",
  "ts-node",
  "esbuild",
  "rollup",
  "framer-motion",
  "wouter",
  "zustand",
  "redux",
  "immer",
  "formik",
  "react-hook-form",
  "tanstack",
];

const POPULAR_SET = new Set(POPULAR_PACKAGES);

// Real, hugely-popular packages that happen to sit one edit from a name in
// POPULAR_PACKAGES. Without this allowlist the check accuses legitimate,
// top-downloads packages (preact ~ react, mysql ~ mysql2) of being
// attacker-registered typosquats — a trust-destroying false positive.
const KNOWN_LEGIT_NEIGHBORS: readonly string[] = [
  "preact", // react
  "mysql", // mysql2
  "redis", // ioredis-adjacent / standalone real package
  "router", // wouter
  "remix", // near several stems
  "nuxt", // next
  "reactn", // react
];
const KNOWN_LEGIT_SET = new Set(KNOWN_LEGIT_NEIGHBORS);

// Optimal string alignment distance (Levenshtein + adjacent transposition).
// Cheap and adequate for one-edit typosquat detection on short names.
function editDistanceLE1(a: string, b: string): boolean {
  if (a === b) return false; // identical is not a typosquat
  if (Math.abs(a.length - b.length) > 1) return false;
  const la = a.length;
  const lb = b.length;
  const dp: number[][] = Array.from({ length: la + 1 }, () =>
    new Array<number>(lb + 1).fill(0),
  );
  for (let i = 0; i <= la; i++) dp[i]![0] = i;
  for (let j = 0; j <= lb; j++) dp[0]![j] = j;
  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(
        dp[i - 1]![j]! + 1,
        dp[i]![j - 1]! + 1,
        dp[i - 1]![j - 1]! + cost,
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, dp[i - 2]![j - 2]! + 1);
      }
      dp[i]![j] = v;
    }
  }
  return dp[la]![lb]! <= 1;
}

function nearestPopular(name: string): string | null {
  for (const pkg of POPULAR_PACKAGES) {
    if (pkg.length < 5) continue;
    if (editDistanceLE1(name, pkg)) return pkg;
  }
  return null;
}

function collectDeps(json: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return [];
  }
  if (typeof parsed !== "object" || parsed === null) return [];
  const record = parsed as Record<string, unknown>;
  const names = new Set<string>();
  for (const field of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    const block = record[field];
    if (typeof block === "object" && block !== null) {
      for (const key of Object.keys(block)) names.add(key);
    }
  }
  return [...names];
}

export async function checkDependencyIntegrity(
  ctx: CheckContext,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const flagged = new Set<string>();
  for (const file of ctx.files) {
    if (path.basename(file.relPath) !== "package.json") continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    for (const dep of collectDeps(content)) {
      // Skip scoped packages (@scope/name): the scope namespace is
      // registry-owned and far harder to squat; unscoping to compare would
      // over-flag legitimate scoped packages.
      if (dep.startsWith("@")) continue;
      if (POPULAR_SET.has(dep)) continue;
      if (KNOWN_LEGIT_SET.has(dep)) continue;
      if (flagged.has(dep)) continue;
      const near = nearestPopular(dep);
      if (!near) continue;
      flagged.add(dep);
      findings.push(
        makeFinding({
          checkId: "dependency-integrity",
          itemId: "dependency-integrity",
          severity: "medium",
          message: `Dependency "${dep}" is one character off "${near}". AI builders hallucinate package names and attackers pre-register them — verify "${dep}" is the real, maintained package before trusting it.`,
          file: relPosix(file.relPath),
          evidence: `"${dep}" resembles the popular package "${near}"`,
        }),
      );
    }
  }
  return findings.slice(0, 25);
}
