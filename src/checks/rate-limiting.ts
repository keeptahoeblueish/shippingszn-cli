import * as path from "node:path";
import { isTextFile, readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";
import { makeFinding } from "./make-finding.js";

// Detects API-route-shaped projects without a visible rate-limit
// dependency. Vibe-coded apps regularly ship public-facing APIs with
// zero throttling, which is how brute-force, scraping, and bot-abuse
// damage gets done. The check is intentionally coarse-grained — it
// keys off package.json deps + a single sweep for a rate-limit signal
// in source — so false positives stay low.

const SERVER_FRAMEWORK_DEPS = new Set([
  "express",
  "fastify",
  "hono",
  "koa",
  "@nestjs/core",
  "next",
  "@sveltejs/kit",
  "astro",
  "@hono/node-server",
  "@trpc/server",
  "elysia",
  "h3",
]);

const RATE_LIMIT_DEPS = new Set([
  "express-rate-limit",
  "@upstash/ratelimit",
  "fastify-rate-limit",
  "@fastify/rate-limit",
  "hono-rate-limiter",
  "rate-limiter-flexible",
  "express-slow-down",
  "@vercel/firewall",
  "@arcjet/next",
  "@arcjet/node",
  "@arcjet/sveltekit",
  "@arcjet/bun",
  "p-limit",
  "p-throttle",
  "bottleneck",
  "limiter",
  "@upstash/redis",
]);

const RATE_LIMIT_SOURCE_REGEX =
  /\b(rateLimit\(|rateLimiter\(|@upstash\/ratelimit|express-rate-limit|fastify-rate-limit|@arcjet|RateLimiter\(|new\s+Bottleneck\s*\(|throttle\(|withRateLimit)\b/i;

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

function depsFromPackage(pkg: PackageJson): Set<string> {
  const all = new Set<string>();
  for (const dep of [
    pkg.dependencies,
    pkg.devDependencies,
    pkg.peerDependencies,
  ]) {
    if (!dep) continue;
    for (const name of Object.keys(dep)) all.add(name);
  }
  return all;
}

export async function checkRateLimiting(ctx: CheckContext): Promise<Finding[]> {
  // Aggregate deps across EVERY package.json (basename match), so a monorepo
  // whose server framework lives in artifacts/*/package.json or packages/*
  // doesn't escape the check by having a bare workspace-root manifest. Matches
  // how dependency-integrity reads manifests.
  const deps = new Set<string>();
  let sawPackageJson = false;
  for (const file of ctx.files) {
    if (path.basename(file.relPath) !== "package.json") continue;
    const raw = await readFileSafe(file);
    if (!raw) continue;
    sawPackageJson = true;
    try {
      const pkg = JSON.parse(raw) as PackageJson;
      for (const d of depsFromPackage(pkg)) deps.add(d);
    } catch {
      // ignore malformed manifests
    }
  }
  if (!sawPackageJson) return [];

  const hasServerFramework = [...deps].some((d) =>
    SERVER_FRAMEWORK_DEPS.has(d),
  );
  if (!hasServerFramework) return [];

  const hasRateLimitDep = [...deps].some((d) => RATE_LIMIT_DEPS.has(d));
  if (hasRateLimitDep) return [];

  // No rate-limit dep — fall back to a source sweep before flagging,
  // since some teams hand-roll throttling.
  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    const ext = path.extname(file.relPath).toLowerCase();
    if (![".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"].includes(ext)) continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    if (RATE_LIMIT_SOURCE_REGEX.test(content)) return [];
  }

  return [
    makeFinding({
      checkId: "rate-limit-missing",
      itemId: "rate-limiting",
      severity: "high",
      message:
        "No rate-limit dependency or in-source throttle was detected. A public API without rate limits will be brute-forced or scraped within days of launch.",
      file: "package.json",
      evidence:
        "package.json declares a server framework (express / fastify / hono / next / etc.) but no rate-limit package and no rate-limit source signal was found.",
    }),
  ];
}
