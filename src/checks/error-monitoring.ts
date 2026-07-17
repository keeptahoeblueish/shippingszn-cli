import * as path from "node:path";
import { isTextFile, readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";
import { makeFinding } from "./make-finding.js";

// Detects projects shipping without an error-monitoring SDK wired up.
// Errors that don't get captured = silent failures in production. The
// check looks for known SDKs in package.json deps OR import sites in
// source. False-positive avoidance > recall here.

const ERROR_MONITORING_DEPS = new Set([
  "@sentry/node",
  "@sentry/nextjs",
  "@sentry/react",
  "@sentry/browser",
  "@sentry/sveltekit",
  "@sentry/astro",
  "@sentry/remix",
  "@sentry/bun",
  "@sentry/vite-plugin",
  "@bugsnag/js",
  "@bugsnag/node",
  "@bugsnag/react",
  "rollbar",
  "@datadog/browser-rum",
  "dd-trace",
  "@honeybadger-io/js",
  "@honeybadger-io/react",
  "@highlight-run/node",
  "@highlight-run/react",
  "@logsnag/node",
  "@axiomhq/js",
  "@axiomhq/react",
  "newrelic",
  "elastic-apm-node",
  "@opentelemetry/api",
]);

const ERROR_MONITORING_SOURCE_REGEX =
  /\b(Sentry\.init|Sentry\.captureException|Bugsnag\.start|bugsnag\(|Rollbar\.init|Honeybadger\.configure|datadogRum\.init|newrelic\.recordCustomEvent|tracer\.init|@sentry\/|@bugsnag\/|@datadog\/|@highlight-run\/|@honeybadger-io)\b/i;

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export async function checkErrorMonitoring(
  ctx: CheckContext,
): Promise<Finding[]> {
  // Aggregate deps across EVERY package.json (basename match), so a monorepo
  // whose error-monitoring SDK lives in artifacts/*/package.json or packages/*
  // doesn't escape the check by having a bare workspace-root manifest. Matches
  // how dependency-integrity / rate-limiting read manifests.
  const deps = new Set<string>();
  let sawPackageJson = false;
  for (const file of ctx.files) {
    if (path.basename(file.relPath) !== "package.json") continue;
    const raw = await readFileSafe(file);
    if (!raw) continue;
    sawPackageJson = true;
    try {
      const pkg = JSON.parse(raw) as PackageJson;
      for (const name of Object.keys(pkg.dependencies ?? {})) deps.add(name);
      for (const name of Object.keys(pkg.devDependencies ?? {})) deps.add(name);
    } catch {
      // ignore malformed manifests
    }
  }
  if (!sawPackageJson) return [];

  if ([...deps].some((d) => ERROR_MONITORING_DEPS.has(d))) return [];

  // Source sweep — some teams hand-roll error capture via fetch wrappers.
  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    if (ERROR_MONITORING_SOURCE_REGEX.test(content)) return [];
  }

  return [
    makeFinding({
      checkId: "error-monitoring-missing",
      itemId: "error-monitoring",
      severity: "medium",
      message:
        "No error-monitoring SDK detected (Sentry / Bugsnag / Rollbar / Datadog / Honeybadger / Highlight / etc.). Production errors that don't get captured become silent failures and shipping bugs.",
      file: "package.json",
      evidence:
        "package.json has no error-monitoring dependency and no error-tracking source signal was found.",
    }),
  ];
}
