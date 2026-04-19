import * as path from "node:path";
import { fileExists, isTextFile, readFileSafe } from "../scan.js";
import type { Severity } from "../items.js";
import type { CheckContext, Finding } from "./types.js";
import { findLine, isScanExempt, relPosix } from "./helpers.js";

interface SecretPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "openai-key",
    name: "OpenAI API key",
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/,
    severity: "critical",
  },
  {
    id: "anthropic-key",
    name: "Anthropic API key",
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
    severity: "critical",
  },
  {
    id: "stripe-live-secret",
    name: "Stripe live secret key",
    regex: /\bsk_live_[A-Za-z0-9]{16,}\b/,
    severity: "critical",
  },
  {
    id: "stripe-live-publishable",
    name: "Stripe live publishable key",
    regex: /\bpk_live_[A-Za-z0-9]{16,}\b/,
    severity: "high",
  },
  {
    id: "aws-access-key",
    name: "AWS access key id",
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    severity: "critical",
  },
  {
    id: "google-api-key",
    name: "Google API key",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: "critical",
  },
  {
    id: "github-token",
    name: "GitHub personal access token",
    regex: /\bghp_[A-Za-z0-9]{30,}\b/,
    severity: "critical",
  },
  {
    id: "slack-token",
    name: "Slack token",
    regex: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
    severity: "high",
  },
  {
    id: "private-key-block",
    name: "Private key block",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    id: "notion-token",
    name: "Notion integration token",
    regex: /\bsecret_[A-Za-z0-9]{43}\b/,
    severity: "critical",
  },
  {
    id: "vercel-token",
    name: "Vercel token",
    regex:
      /\b(?:VERCEL_TOKEN|vercel_token|vercelToken)\b\s*[:=]\s*['"]?[A-Za-z0-9]{24}['"]?/,
    severity: "critical",
  },
  {
    id: "sendgrid-api-key",
    name: "SendGrid API key",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
    severity: "critical",
  },
  {
    id: "twilio-account-sid",
    name: "Twilio Account SID",
    regex: /\bAC[a-f0-9]{32}\b/,
    severity: "high",
  },
];

const JWT_REGEX =
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

function tryDecodeJwtPayload(token: string): string | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let b = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  while (b.length % 4 !== 0) b += "=";
  try {
    return Buffer.from(b, "base64").toString("utf8");
  } catch {
    return null;
  }
}

const SECRET_SCAN_SKIP_NAMES = new Set([
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
]);

export async function checkHardcodedSecrets(
  ctx: CheckContext,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const file of ctx.files) {
    const base = path.basename(file.relPath);
    if (SECRET_SCAN_SKIP_NAMES.has(base)) continue;
    if (!isTextFile(file)) continue;
    if (isScanExempt(file.relPath)) continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    const isEnvExample =
      /\.example$|\.sample$|\.template$/i.test(base) || base === ".env.example";
    if (isEnvExample) continue;
    const matchedRanges: Array<[number, number]> = [];
    for (const pat of SECRET_PATTERNS) {
      const m = pat.regex.exec(content);
      if (!m) continue;
      const start = m.index;
      const end = m.index + m[0].length;
      if (matchedRanges.some(([s, e]) => start < e && end > s)) continue;
      matchedRanges.push([start, end]);
      const line = findLine(content, start);
      findings.push({
        checkId: `secret-${pat.id}`,
        itemId: "secrets",
        severity: pat.severity,
        message: `Possible ${pat.name} hardcoded in source.`,
        file: relPosix(file.relPath),
        line,
        evidence: `${m[0].slice(0, 6)}…${m[0].slice(-4)} (${m[0].length} chars)`,
      });
    }

    JWT_REGEX.lastIndex = 0;
    let jm: RegExpExecArray | null;
    while ((jm = JWT_REGEX.exec(content)) !== null) {
      const start = jm.index;
      const end = jm.index + jm[0].length;
      if (matchedRanges.some(([s, e]) => start < e && end > s)) continue;
      matchedRanges.push([start, end]);
      const payload = tryDecodeJwtPayload(jm[0]);
      const isServiceRole =
        !!payload && /"role"\s*:\s*"service_role"/.test(payload);
      const line = findLine(content, start);
      if (isServiceRole) {
        findings.push({
          checkId: "secret-supabase-service-role-jwt",
          itemId: "secrets",
          severity: "critical",
          message: "Possible Supabase service-role JWT hardcoded in source.",
          file: relPosix(file.relPath),
          line,
          evidence: `${jm[0].slice(0, 6)}…${jm[0].slice(-4)} (${jm[0].length} chars)`,
        });
      } else {
        findings.push({
          checkId: "secret-jwt",
          itemId: "secrets",
          severity: "high",
          message: "Possible JWT hardcoded in source.",
          file: relPosix(file.relPath),
          line,
          evidence: `${jm[0].slice(0, 6)}…${jm[0].slice(-4)} (${jm[0].length} chars)`,
        });
      }
      break;
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Config-file secret leaks
//
// Catches the class of bug where a credential-shaped value gets hardcoded into
// a tracked config file (.env, *.toml) under an env-var assignment, and the
// related anti-pattern of naming a browser-exposed VITE_ variable like a
// secret (VITE_*_SECRET / TOKEN / KEY / PASSWORD). Anything with the VITE_
// prefix is baked into the client bundle by Vite at build time and is
// readable by every visitor — naming it like a secret gives false comfort.
// ---------------------------------------------------------------------------

const CONFIG_FILE_BASENAMES = new Set([
  ".env",
  ".env.local",
  ".env.production",
]);
const CONFIG_FILE_EXTENSIONS = new Set([".toml"]);

function looksLikeConfigFile(relPath: string): boolean {
  const base = path.basename(relPath);
  if (CONFIG_FILE_BASENAMES.has(base)) return true;
  const ext = path.extname(base).toLowerCase();
  if (CONFIG_FILE_EXTENSIONS.has(ext)) return true;
  return false;
}

const CONFIG_ASSIGNMENT_REGEX =
  /^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(?:"([^"\n]+)"|'([^'\n]+)'|([^\s#"'][^\s#]*))/gm;
const VITE_SECRET_KEY_REGEX =
  /^VITE_[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|PRIVATE)$/;
const HEX_SECRET_REGEX = /^[A-Fa-f0-9]{32,}$/;
const BASE64_SECRET_REGEX = /^[A-Za-z0-9+/_-]{40,}={0,2}$/;
const TEMPLATED_VALUE_REGEX = /\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*/;

const CONFIG_KEY_ALLOWLIST = new Set([
  "DATABASE_URL", // contains URL/host fragments, handled by other rules
]);

export async function checkConfigSecretLeaks(
  ctx: CheckContext,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const file of ctx.files) {
    if (!looksLikeConfigFile(file.relPath)) continue;
    if (!isTextFile(file)) continue;
    const base = path.basename(file.relPath);
    if (/\.example$|\.sample$|\.template$/i.test(base)) continue;
    const content = await readFileSafe(file);
    if (!content) continue;

    CONFIG_ASSIGNMENT_REGEX.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = CONFIG_ASSIGNMENT_REGEX.exec(content)) !== null) {
      const key = m[1];
      const value = (m[2] ?? m[3] ?? m[4] ?? "").trim();
      if (!value) continue;
      if (TEMPLATED_VALUE_REGEX.test(value)) continue;
      const line = findLine(content, m.index);

      // 1. Browser-exposed VITE_ variable named like a secret. Severity: high
      //    regardless of value, because the *name* itself is the bug.
      if (VITE_SECRET_KEY_REGEX.test(key)) {
        findings.push({
          checkId: "config-vite-prefixed-secret",
          itemId: "secrets",
          severity: "high",
          message: `${key} is set in ${relPosix(file.relPath)}. Variables prefixed with VITE_ are baked into the browser bundle by Vite at build time and are readable by every visitor — they are not secrets. Rename the variable (drop VITE_) and access it server-side only, or move the signing/auth flow behind a backend endpoint.`,
          file: relPosix(file.relPath),
          line,
          evidence: `${key}=${value.slice(0, 4)}…${value.slice(-2)} (${value.length} chars)`,
        });
        continue;
      }

      // 2. Anything else: high-entropy hardcoded credential value.
      if (CONFIG_KEY_ALLOWLIST.has(key)) continue;
      const isHex = HEX_SECRET_REGEX.test(value);
      const isBase64 = BASE64_SECRET_REGEX.test(value);
      if (!isHex && !isBase64) continue;

      findings.push({
        checkId: "config-hardcoded-credential",
        itemId: "secrets",
        severity: "critical",
        message: `${key} in ${relPosix(file.relPath)} looks like a hardcoded credential (${value.length}-char ${isHex ? "hex" : "base64-shaped"} value). Move it to your platform's secret store (Railway / Vercel / Fly env vars, or a dedicated vault) and reference it from there. Rotate the leaked value at the source.`,
        file: relPosix(file.relPath),
        line,
        evidence: `${key}=${value.slice(0, 4)}…${value.slice(-2)} (${value.length} chars)`,
      });
    }
  }
  return findings;
}

// fileExists is referenced indirectly only via env.ts; re-exported for backwards compat
export { fileExists };
