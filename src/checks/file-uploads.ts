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

// Detects file-upload library usage without an obvious size/type guard
// nearby. Conservative: only fires when an upload library is actually
// imported AND used, not just present in deps. Wording is "no obvious
// evidence found" — owner must verify the upstream limits.

const UPLOAD_LIBRARY_DEPS = new Set([
  "multer",
  "busboy",
  "formidable",
  "@fastify/multipart",
  "express-fileupload",
  "@hono/node-server",
  "uploadthing",
  "@uploadthing/react",
  "react-dropzone",
]);

// Source signals — be specific, avoid generic "upload" hits.
const UPLOAD_USAGE_PATTERNS: ReadonlyArray<{
  regex: RegExp;
  provider: string;
}> = [
  { regex: /\bmulter\s*\(/, provider: "multer" },
  { regex: /\bnew\s+Busboy\s*\(/, provider: "busboy" },
  { regex: /\bnew\s+IncomingForm\s*\(/, provider: "formidable" },
  { regex: /\bcreateUploadthing\s*\(/, provider: "uploadthing" },
  {
    regex: /\bregisterMultipartFormParser\s*\(/,
    provider: "@fastify/multipart",
  },
  {
    regex: /\bapp\.use\s*\(\s*fileUpload\s*\(/,
    provider: "express-fileupload",
  },
];

const SIZE_LIMIT_REGEX =
  /\b(limits\s*:\s*\{|fileSize\s*[:=]\s*[0-9]|maxFileSize|maxSize|maxBytes|fieldSize|maxFiles\s*[:=])\b/;

const TYPE_FILTER_REGEX =
  /\b(mimetype|allowedMimeTypes|fileFilter|allowedExtensions|acceptedFileTypes|accept\s*[:=]\s*\[)\b/i;

const RUNTIME_EXTS: ReadonlySet<string> = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
]);

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export async function checkFileUploads(ctx: CheckContext): Promise<Finding[]> {
  // Aggregate deps across EVERY package.json (basename match), so a monorepo
  // whose upload library lives in artifacts/*/package.json or packages/* doesn't
  // escape the check by having a bare workspace-root manifest. Matches how
  // dependency-integrity / rate-limiting read manifests.
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

  const hasUploadDep = [...deps].some((d) => UPLOAD_LIBRARY_DEPS.has(d));
  if (!hasUploadDep) return [];

  const findings: Finding[] = [];

  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    if (isScanExempt(file.relPath)) continue;
    if (isLikelyNonRuntimePath(file.relPath)) continue;
    if (isUiLibraryPrimitive(file.relPath)) continue;

    const ext = path.extname(file.relPath).toLowerCase();
    if (!RUNTIME_EXTS.has(ext)) continue;

    const content = await readFileSafe(file);
    if (!content) continue;

    let usageHit: { index: number; provider: string } | null = null;
    for (const { regex, provider } of UPLOAD_USAGE_PATTERNS) {
      const m = regex.exec(content);
      if (m) {
        usageHit = { index: m.index, provider };
        break;
      }
    }
    if (!usageHit) continue;

    const start = Math.max(0, usageHit.index - 400);
    const end = Math.min(content.length, usageHit.index + 1200);
    const window = content.slice(start, end);

    const hasSizeLimit = SIZE_LIMIT_REGEX.test(window);
    const hasTypeFilter = TYPE_FILTER_REGEX.test(window);
    if (hasSizeLimit && hasTypeFilter) continue;

    const rel = relPosix(file.relPath);
    const line = findLine(content, usageHit.index);
    const missing: string[] = [];
    if (!hasSizeLimit) missing.push("size limit");
    if (!hasTypeFilter) missing.push("MIME / extension filter");

    findings.push(
      makeFinding({
        checkId: "file-upload-guards-missing",
        itemId: "file-uploads",
        severity: "medium",
        message: `${usageHit.provider} upload usage detected with no obvious ${missing.join(" and ")} nearby. Untyped or unbounded uploads can fill disk, smuggle malware, or trigger expensive processing pipelines. Owner must verify limits exist somewhere in the chain (CDN, edge config, or different file).`,
        file: rel,
        line,
        evidence: `${usageHit.provider} upload call at ${rel}:${line}. No ${missing.join(" / ")} signal in the surrounding window.`,
      }),
    );
    return findings; // one finding per project
  }

  return findings;
}
