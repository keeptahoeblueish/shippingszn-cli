import * as path from "node:path";
import { readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";

const SECURITY_HEADER_NAMES = [
  "Strict-Transport-Security",
  "Content-Security-Policy",
  "X-Content-Type-Options",
  "X-Frame-Options",
  "Referrer-Policy",
];

const CANDIDATE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".mts",
  ".cts",
  ".json",
  ".toml",
]);

const CANDIDATE_BASENAMES = new Set([
  "vite.config.ts",
  "vite.config.js",
  "vite.config.mjs",
  "vite.config.cjs",
  "next.config.js",
  "next.config.mjs",
  "next.config.ts",
  "nuxt.config.ts",
  "svelte.config.js",
  "astro.config.mjs",
  "astro.config.ts",
  "vercel.json",
  "netlify.toml",
]);

// Directories whose files commonly define server / middleware / route /
// header code. We scan every eligible file under these trees, not just a
// single "entry" file, so hand-rolled security-header middleware (e.g.
// a dedicated server/security.ts) is detected just as reliably as helmet().
const CANDIDATE_DIR_SEGMENTS = [
  "server/",
  "api/",
  "backend/",
  "middleware/",
  "middlewares/",
  "lib/server/",
  "src/server/",
  "src/api/",
  "src/middleware/",
  "src/middlewares/",
  "apps/server/",
  "apps/api/",
  "packages/server/",
  "packages/api/",
  "artifacts/server/",
  "artifacts/api-server/",
];

function isCandidateFile(relPath: string): boolean {
  const lower = relPath.replace(/\\/g, "/").toLowerCase();
  if (
    lower.includes("/node_modules/") ||
    lower.includes("/dist/") ||
    lower.includes("/build/") ||
    lower.includes("/.next/") ||
    lower.endsWith(".test.ts") ||
    lower.endsWith(".spec.ts") ||
    lower.endsWith(".test.tsx") ||
    lower.endsWith(".spec.tsx") ||
    lower.endsWith(".test.js") ||
    lower.endsWith(".spec.js")
  ) {
    return false;
  }
  const base = path.basename(lower);
  if (CANDIDATE_BASENAMES.has(base)) return true;
  const ext = path.extname(lower);
  if (!CANDIDATE_EXTENSIONS.has(ext)) return false;
  if (
    /\b(?:server|index|app|main|bootstrap|middleware|security)\.(?:t|j|m|c)?sx?$/.test(
      base,
    )
  ) {
    return true;
  }
  for (const seg of CANDIDATE_DIR_SEGMENTS) {
    if (lower.includes("/" + seg) || lower.startsWith(seg)) return true;
  }
  return false;
}

export async function checkSecurityHeaders(
  ctx: CheckContext,
): Promise<Finding[]> {
  const candidates = ctx.files.filter((f) => isCandidateFile(f.relPath));
  if (candidates.length === 0) return [];

  for (const file of candidates) {
    const content = await readFileSafe(file);
    if (!content) continue;
    const lower = content.toLowerCase();
    for (const h of SECURITY_HEADER_NAMES) {
      if (lower.includes(h.toLowerCase())) return [];
    }
    if (
      lower.includes("helmet(") ||
      lower.includes('require("helmet")') ||
      lower.includes('from "helmet"') ||
      lower.includes("from 'helmet'")
    ) {
      return [];
    }
  }

  return [
    {
      checkId: "missing-security-headers",
      itemId: "https-headers",
      severity: "high",
      message:
        "Couldn't find any common security headers (CSP, HSTS, X-Frame-Options, etc.) or helmet() middleware in your server/host configs. Add them so the browser enforces baseline defenses.",
    },
  ];
}
