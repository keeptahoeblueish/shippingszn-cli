import * as path from "node:path";
import {
  fileExists,
  isTextFile,
  readFileSafe,
  type ScannedFile,
} from "../scan.js";
import type { CheckContext } from "./types.js";

export function relPosix(p: string): string {
  return p.split(path.sep).join("/");
}

export function findLine(content: string, idx: number): number {
  let line = 1;
  for (let i = 0; i < idx; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

/**
 * Inline opt-out markers. Two flavors, both optional:
 *
 * - `shippingszn:ignore` on the same line as the match suppresses it.
 * - `shippingszn:ignore-next-line` on the line ABOVE the match suppresses
 *   it. This exists because formatters (prettier, biome) routinely
 *   reflow trailing comments onto their own line, which would otherwise
 *   silently break the same-line marker. Mirrors the eslint /
 *   prettier-ignore-next conventions.
 *
 * The literal values are split across concatenations so that grep'ing
 * for the marker only finds the *uses*, not these definitions.
 */
export const IGNORE_MARKER = "shippingszn" + ":ignore";
export const IGNORE_NEXT_LINE_MARKER = "shippingszn" + ":ignore-next-line";

function getLine(content: string, charIndex: number): string {
  const lineStart = content.lastIndexOf("\n", charIndex - 1) + 1;
  const lineEnd = content.indexOf("\n", charIndex);
  return content.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
}

function getPreviousLine(content: string, charIndex: number): string | null {
  const lineStart = content.lastIndexOf("\n", charIndex - 1) + 1;
  if (lineStart === 0) return null;
  const prevEnd = lineStart - 1;
  const prevStart = content.lastIndexOf("\n", prevEnd - 1) + 1;
  return content.slice(prevStart, prevEnd);
}

export function lineContainsIgnoreMarker(
  content: string,
  charIndex: number,
): boolean {
  if (getLine(content, charIndex).includes(IGNORE_MARKER)) return true;
  const prev = getPreviousLine(content, charIndex);
  return prev !== null && prev.includes(IGNORE_NEXT_LINE_MARKER);
}

const PUBLIC_DIR_CANDIDATES = [
  "public",
  "static",
  "www",
  "dist",
  "build",
  "out",
];

export async function findPublicDirs(ctx: CheckContext): Promise<string[]> {
  const dirs: string[] = [];
  for (const cand of PUBLIC_DIR_CANDIDATES) {
    const p = path.join(ctx.rootDir, cand);
    if (await fileExists(p)) dirs.push(cand);
  }
  // Also any artifact public dirs in monorepo style.
  const seen = new Set<string>(dirs);
  for (const f of ctx.files) {
    const parts = f.relPath.split("/");
    for (let i = 0; i < parts.length - 1; i++) {
      if (parts[i] === "public" || parts[i] === "static") {
        const dir = parts.slice(0, i + 1).join("/");
        if (!seen.has(dir)) {
          seen.add(dir);
          dirs.push(dir);
        }
      }
    }
  }
  return dirs;
}

/**
 * Narrow per-file exemption for substring/regex checks (placeholder
 * content, dangerous patterns, language patterns).
 *
 * This deliberately does NOT exempt the CLI source or test trees as a
 * whole — broad exemptions hide real bugs. It only lists files that
 * define or document the patterns the scanner looks for, where a literal
 * pattern in source is the file's whole purpose:
 *
 *   - `tools/cli/src/checks/{dangerous,quality,language}.ts` define the
 *     regexes and human-readable messages, both of which contain the
 *     literal pattern strings.
 *   - `tools/cli/README.md` documents what the scanner detects, citing
 *     the pattern strings verbatim.
 *   - `tools/cli/test/fixtures/` contains intentional positive fixtures.
 *   - `artifacts/checklist/src/data/checklist/` is user-facing checklist
 *     copy that names the patterns by name (e.g. "look for TODO/FIXME"). shippingszn:ignore
 *
 * Secret scanning is NOT exempted from any of these paths — the secret
 * regexes contain regex metacharacters in source and don't self-match,
 * so real hardcoded secrets in the CLI source would still be caught.
 *
 * For one-off cases in normal source files, prefer the inline
 * `shippingszn:ignore` marker (handled by lineContainsIgnoreMarker)
 * instead of adding paths here.
 */
const PATTERN_DEFINITION_FILES: ReadonlySet<string> = new Set([
  "tools/cli/src/checks/dangerous.ts",
  "tools/cli/src/checks/quality.ts",
  "tools/cli/src/checks/language.ts",
  "tools/cli/src/checks/otp-auth.ts",
  "tools/cli/src/checks/api-spend-cap.ts",
  "tools/cli/src/checks/session-cookie.ts",
  "tools/cli/README.md",
  // Test fixture for the redaction module: contains intentional fake
  // secret patterns whose whole purpose is to verify the redactor scrubs
  // them. Functionally identical to tools/cli/test/fixtures/, just lives
  // in a different package.
  "artifacts/api-server/src/lib/__tests__/redaction.test.ts",
]);

const PATTERN_DEFINITION_PREFIXES: readonly string[] = [
  "tools/cli/test/fixtures/",
  "artifacts/checklist/src/data/checklist/",
  "lib/checklist-data/src/",
];

export function isScanExempt(relPath: string): boolean {
  const p = relPosix(relPath);
  if (PATTERN_DEFINITION_FILES.has(p)) return true;
  for (const prefix of PATTERN_DEFINITION_PREFIXES) {
    if (p.startsWith(prefix) || p.includes("/" + prefix)) return true;
  }
  return false;
}

export function isLikelyNonRuntimePath(relPath: string): boolean {
  const p = relPosix(relPath).toLowerCase();
  const base = path.basename(p);
  if (base.endsWith(".d.ts")) return true;
  if (
    /\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/.test(base) ||
    p.includes("/__tests__/") ||
    p.includes("/test/") ||
    p.includes("/tests/")
  ) {
    return true;
  }
  if (p === "claude.md" || p === "agents.md" || p === "devops.md") return true;
  if (
    p.startsWith("docs/") ||
    p.includes("/docs/") ||
    p.startsWith("scripts/") ||
    p.includes("/scripts/") ||
    p.startsWith("examples/") ||
    p.includes("/examples/") ||
    p.startsWith("artifacts/mockup-sandbox/") ||
    p.includes("/artifacts/mockup-sandbox/")
  ) {
    return true;
  }
  return false;
}

// shadcn/ui-style UI primitives live under `components/ui/*` by convention.
// They are LIBRARY code — not the app's auth flow, not where the framework's
// HTML-injection prop is a real risk. Flagging them as launch blockers
// produces false positives on every shadcn-using vibe-coded project.
// Used by dangerous.ts and otp-auth.ts to skip these paths.
export function isUiLibraryPrimitive(relPath: string): boolean {
  const p = relPosix(relPath).toLowerCase();
  return (
    p.startsWith("components/ui/") ||
    p.includes("/components/ui/") ||
    p.startsWith("src/components/ui/") ||
    p.includes("/src/components/ui/") ||
    p.startsWith("app/components/ui/") ||
    p.includes("/app/components/ui/") ||
    p.startsWith("ui/") ||
    p.includes("/shadcn/ui/")
  );
}

/**
 * Does any source file in the project look like it dynamically emits or
 * serves the given asset (e.g. `robots.txt`, `sitemap.xml`)? Used by
 * `checkRobotsTxt` / `checkSitemapXml` to suppress false positives in
 * projects that generate these at build time via a Vite plugin or serve
 * them from an Express/Next route.
 *
 * Heuristic: a `.ts`/`.js`/`.mjs`/`.cjs` source file that mentions the
 * asset filename as a string literal AND contains an emission/serve
 * indicator (`emitFile`, `setHeader`, `res.end`, `res.send`,
 * `configureServer`, `app.get`, `router.get`, `next/headers`).
 */
const SERVE_INDICATORS = [
  "emitFile",
  "setHeader",
  "res.end",
  "res.send",
  "configureServer",
  "configurePreviewServer",
  "app.get",
  "app.use",
  "router.get",
  "router.use",
];

const DYNAMIC_ASSET_SOURCE_EXTS: ReadonlySet<string> = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
]);

export async function isAssetEmittedDynamically(
  ctx: CheckContext,
  assetName: string,
): Promise<boolean> {
  const literalPatterns = [`"${assetName}"`, `'${assetName}'`, `/${assetName}`];
  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    const ext = path.extname(file.relPath).toLowerCase();
    if (!DYNAMIC_ASSET_SOURCE_EXTS.has(ext)) continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    if (!literalPatterns.some((p) => content.includes(p))) continue;
    if (!SERVE_INDICATORS.some((s) => content.includes(s))) continue;
    return true;
  }
  return false;
}
