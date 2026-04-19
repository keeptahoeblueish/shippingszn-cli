/**
 * Anonymous auto-publish of scan results to the Wall of Launches at
 * shippingszn.com. Runs once per scan, best-effort. Never blocks the CLI
 * on network failure — if anything goes wrong we fail silently and the
 * scan result still prints normally.
 *
 * Absolute guarantees about the payload: no secrets, no paths, no
 * filenames, no project-name-derived strings. The only thing we send
 * is: files scanned count, findings counts by severity, detected stack
 * tags, scanner version. Users can opt out entirely by setting
 * SHIPPINGSZN_DISABLE_PUBLISH=1 in their environment.
 */
import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { Severity } from "./items.js";

const DEFAULT_BASE_URL = "https://shippingszn.com";
const PUBLISH_TIMEOUT_MS = 3000;

export interface PublishPayload {
  filesScanned: number;
  findingsCritical: number;
  findingsHigh: number;
  findingsMedium: number;
  findingsLower: number;
  stack?: string[];
  scannerVersion?: string;
}

export interface PublishOptions {
  cwd: string;
  baseUrl?: string;
  scannerVersion: string;
}

function shouldPublish(): boolean {
  const v = process.env["SHIPPINGSZN_DISABLE_PUBLISH"] ?? "";
  return v !== "1" && v.toLowerCase() !== "true" && v !== "yes";
}

// Detect a small list of tech-stack tags from package.json / manifest
// files. Deliberately shallow: we only want a handful of widely-known
// framework tags. Nothing else is read or transmitted.
async function detectStack(cwd: string): Promise<string[]> {
  const tags = new Set<string>();
  try {
    const raw = await fs.readFile(path.join(cwd, "package.json"), "utf8");
    const pkg = JSON.parse(raw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    const has = (n: string) => n in deps;
    if (has("react")) tags.add("react");
    if (has("next")) tags.add("next");
    if (has("vue") || has("nuxt")) tags.add("vue");
    if (has("svelte") || has("@sveltejs/kit")) tags.add("svelte");
    if (has("astro")) tags.add("astro");
    if (has("express")) tags.add("express");
    if (has("fastify")) tags.add("fastify");
    if (has("hono")) tags.add("hono");
    if (has("drizzle-orm")) tags.add("drizzle");
    if (has("prisma")) tags.add("prisma");
    if (has("@supabase/supabase-js")) tags.add("supabase");
    if (has("firebase")) tags.add("firebase");
    if (has("stripe")) tags.add("stripe");
    if (has("typescript")) tags.add("ts");
    if (has("vite")) tags.add("vite");
    if (has("expo")) tags.add("expo");
    if (has("react-native")) tags.add("react-native");
  } catch {
    /* no package.json — not a node project, that's fine */
  }
  // Language/framework detection beyond node — cheap file-existence checks.
  const checks: Array<[string, string]> = [
    ["requirements.txt", "python"],
    ["pyproject.toml", "python"],
    ["Gemfile", "ruby"],
    ["go.mod", "go"],
    ["Cargo.toml", "rust"],
    ["composer.json", "php"],
    ["pom.xml", "java"],
    ["build.gradle", "java"],
  ];
  for (const [file, tag] of checks) {
    try {
      await fs.access(path.join(cwd, file));
      tags.add(tag);
    } catch {
      /* not present */
    }
  }
  return [...tags].slice(0, 12);
}

export function buildPayload(
  totals: Record<Severity, number>,
  filesScanned: number,
  stack: string[],
  scannerVersion: string,
): PublishPayload {
  const out: PublishPayload = {
    filesScanned,
    findingsCritical: totals.critical ?? 0,
    findingsHigh: totals.high ?? 0,
    findingsMedium: totals.medium ?? 0,
    findingsLower: totals.lower ?? 0,
    scannerVersion,
  };
  if (stack.length > 0) out.stack = stack;
  return out;
}

export async function publishScan(
  totals: Record<Severity, number>,
  filesScanned: number,
  opts: PublishOptions,
): Promise<"published" | "skipped" | "failed"> {
  if (!shouldPublish()) return "skipped";
  const baseUrl = opts.baseUrl ?? DEFAULT_BASE_URL;
  const stack = await detectStack(opts.cwd);
  const payload = buildPayload(
    totals,
    filesScanned,
    stack,
    opts.scannerVersion,
  );
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PUBLISH_TIMEOUT_MS);
  try {
    const res = await fetch(`${baseUrl}/api/wall`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timer);
    return res.ok ? "published" : "failed";
  } catch {
    clearTimeout(timer);
    return "failed";
  }
}
