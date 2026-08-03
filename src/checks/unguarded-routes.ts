import * as path from "node:path";
import { isTextFile, readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";
import {
  findLine,
  isLikelyNonRuntimePath,
  isScanExempt,
  isUiLibraryPrimitive,
  relPosix,
} from "./helpers.js";
import { makeFinding } from "./make-finding.js";

// Detects route handlers that match admin / write / destructive patterns
// AND have no obvious auth-shaped middleware or check in the surrounding
// window. Conservative wording: we say "no obvious auth-guard nearby",
// not "this route is unauthenticated". Owner must verify the upstream
// middleware stack actually protects this path.
//
// Confidence: PARTIAL — finds the strong cases, misses session-cookie
// auth that's enforced by a wrapping middleware out of file scope.

const RISKY_ROUTE_PATTERNS: ReadonlyArray<{
  regex: RegExp;
  shape: string;
}> = [
  {
    regex:
      /\b(app|router)\.(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]*\/(admin|internal|admin-api|management|console|backoffice)\b[^"'`]*)["'`]/g,
    shape: "admin/internal route",
  },
  {
    regex: /\b(app|router)\.(delete)\s*\(\s*["'`]([^"'`]+)["'`]/g,
    shape: "DELETE route",
  },
  {
    regex:
      /\b(app|router)\.(post|put|patch)\s*\(\s*["'`]([^"'`]*\/(reset|impersonate|seed|wipe|drop|nuke|migrate|admin)[^"'`]*)["'`]/g,
    shape: "destructive write route",
  },
];

// Auth-shaped middleware names — names we recognize as a guard.
// Conservative: prefer false negatives over false positives. If your
// auth middleware uses an unusual name we miss, we'll skip over your
// route silently — better than mislabeling.
const AUTH_GUARD_REGEX =
  /\b(requireAuth|requireUser|requireAdmin|requireAdminSession|requireSession|requireMcpSession|isAuthenticated|isAdmin|withAuth|protect\s*\(|authenticate\s*\(|authMiddleware|verifySession|getServerSession|currentUser\s*\(|auth\.guard|sessionGuard|verifyToken)\b/;

const RUNTIME_EXTS: ReadonlySet<string> = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
]);

export async function checkUnguardedRoutes(
  ctx: CheckContext,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const seenFiles = new Set<string>();

  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    if (isScanExempt(file.relPath)) continue;
    if (isLikelyNonRuntimePath(file.relPath)) continue;
    if (isUiLibraryPrimitive(file.relPath)) continue;

    const ext = path.extname(file.relPath).toLowerCase();
    if (!RUNTIME_EXTS.has(ext)) continue;

    const content = await readFileSafe(file);
    if (!content) continue;
    const rel = relPosix(file.relPath);
    if (seenFiles.has(rel)) continue;

    // If the file has an auth guard ANYWHERE, treat the file as
    // potentially-guarded and don't flag (conservative).
    if (AUTH_GUARD_REGEX.test(content)) continue;

    for (const { regex, shape } of RISKY_ROUTE_PATTERNS) {
      regex.lastIndex = 0;
      const m = regex.exec(content);
      if (!m) continue;

      const line = findLine(content, m.index);
      const routePath = m[3] ?? m[2] ?? "(unknown)";

      findings.push(
        makeFinding({
          checkId: "unguarded-route",
          itemId: "secure-api",
          severity: "high",
          message: `${shape} bound at ${rel}:${line} (path: ${routePath}). No obvious auth-guard middleware (requireAuth / isAdmin / withAuth / getServerSession / similar) was found anywhere in this file. Owner must verify the route is protected by a wrapping middleware, framework convention, or different file — this scanner cannot trace the middleware chain across files.`,
          file: rel,
          line,
          evidence: `${shape} declared at ${rel}:${line}. No recognized auth-guard symbol present in the file.`,
        }),
      );
      seenFiles.add(rel);
      break;
    }
  }

  return findings;
}
