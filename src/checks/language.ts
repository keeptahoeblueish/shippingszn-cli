import * as path from "node:path";
import { isTextFile, readFileSafe, type ScannedFile } from "../scan.js";
import type { Severity } from "../items.js";
import type { CheckContext, Finding } from "./types.js";
import { findLine, relPosix } from "./helpers.js";

interface LangPattern {
  id: string;
  regex: RegExp;
  itemId: string;
  severity: Severity;
  message: string;
}

const PYTHON_PATTERNS: LangPattern[] = [
  {
    id: "py-pickle-loads",
    regex: /\bpickle\s*\.\s*loads?\s*\(/,
    itemId: "common-attacks",
    severity: "high",
    message:
      "Use of pickle.loads / pickle.load — deserializing pickle data from untrusted sources allows arbitrary code execution. Use json or another safe format.",
  },
  {
    id: "py-subprocess-shell-true",
    regex: /\bshell\s*=\s*True\b/,
    itemId: "common-attacks",
    severity: "high",
    message:
      "subprocess call with shell=True — if any argument is user-controlled this is a shell injection. Pass an argv list instead.",
  },
  {
    id: "py-flask-debug-true",
    regex: /\.run\s*\([^)]*\bdebug\s*=\s*True/,
    itemId: "dev-prod-data",
    severity: "high",
    message:
      "Flask app.run(debug=True) — Werkzeug's debugger exposes a remote Python shell. Never enable this in production; gate on an env var.",
  },
  {
    id: "py-django-debug-true",
    regex: /^\s*DEBUG\s*=\s*True\b/m,
    itemId: "dev-prod-data",
    severity: "high",
    message:
      "Django DEBUG = True at module scope — leaks stack traces, settings, and SQL to anyone who hits an error page in production. Read it from an env var.",
  },
  {
    id: "py-hardcoded-secret-key",
    regex: /^\s*SECRET_KEY\s*=\s*['"][^'"\n]{8,}['"]/m,
    itemId: "secrets",
    severity: "critical",
    message:
      "Hardcoded SECRET_KEY in a Django/Flask settings file. Load it from os.environ / os.getenv instead and keep the real value out of source control.",
  },
];

const RUBY_PATTERNS: LangPattern[] = [
  {
    id: "rb-eval",
    regex: /(^|[^A-Za-z0-9_])eval\s*\(/,
    itemId: "common-attacks",
    severity: "high",
    message:
      "Use of eval in Ruby — executes arbitrary code and is almost always avoidable. Replace with safer alternatives like send, public_send, or a hash lookup.",
  },
  {
    id: "rb-html-safe",
    regex: /\.html_safe\b/,
    itemId: "common-attacks",
    severity: "medium",
    message:
      "Call to .html_safe in Ruby/Rails — bypasses ERB's automatic HTML escaping. Make sure the string isn't user-controlled or you'll have an XSS hole.",
  },
  {
    id: "rb-hardcoded-secret-key-base",
    regex: /^\s*secret_key_base\s*:\s*['"]?[A-Za-z0-9]{16,}['"]?/m,
    itemId: "secrets",
    severity: "critical",
    message:
      "Hardcoded secret_key_base in a Rails config/credentials file. Move it to ENV['SECRET_KEY_BASE'] or Rails' encrypted credentials.",
  },
];

const GO_PATTERNS: LangPattern[] = [
  {
    id: "go-listen-and-serve-no-tls",
    regex: /\bhttp\s*\.\s*ListenAndServe\s*\(/,
    itemId: "https-headers",
    severity: "high",
    message:
      "http.ListenAndServe — serves plain HTTP with no TLS. Use http.ListenAndServeTLS, terminate TLS at a proxy, or run behind a managed host that does.",
  },
  {
    id: "go-hardcoded-token-literal",
    regex: /\b(?:token|apiKey|api_key|secret)\s*(?::=|=)\s*"[A-Za-z0-9_\-]{20,}"/i,
    itemId: "secrets",
    severity: "high",
    message:
      "Hardcoded token/secret literal in Go source. Read it from os.Getenv or a secret manager instead of compiling it into the binary.",
  },
];

const RAILS_YAML_PATTERNS: LangPattern[] = [
  RUBY_PATTERNS.find((p) => p.id === "rb-hardcoded-secret-key-base")!,
];

const LANG_PATTERN_SETS: Array<{ exts: string[]; patterns: LangPattern[] }> = [
  { exts: [".py"], patterns: PYTHON_PATTERNS },
  { exts: [".rb", ".erb"], patterns: RUBY_PATTERNS },
  { exts: [".yml", ".yaml"], patterns: RAILS_YAML_PATTERNS },
  { exts: [".go"], patterns: GO_PATTERNS },
];

export async function checkLanguagePatterns(ctx: CheckContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    const ext = path.extname(file.relPath).toLowerCase();
    const set = LANG_PATTERN_SETS.find((s) => s.exts.includes(ext));
    if (!set) continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    for (const pat of set.patterns) {
      const m = pat.regex.exec(content);
      if (!m) continue;
      const line = findLine(content, m.index);
      findings.push({
        checkId: pat.id,
        itemId: pat.itemId,
        severity: pat.severity,
        message: pat.message,
        file: relPosix(file.relPath),
        line,
      });
    }
  }
  return findings;
}

function isPythonSettingsLike(relPath: string, content: string): boolean {
  const base = path.basename(relPath).toLowerCase();
  if (base === "settings.py" || base === "config.py" || base === "app.py" || base === "wsgi.py" || base === "asgi.py") {
    return true;
  }
  if (/\bfrom\s+django\b/.test(content) || /\bimport\s+django\b/.test(content)) return true;
  if (/\bfrom\s+flask\s+import\b/.test(content) || /\bFlask\s*\(/.test(content)) return true;
  return false;
}

function pythonReadsSecretKeyFromEnv(content: string): boolean {
  const envRefs = [
    /SECRET_KEY\s*=\s*os\.environ(?:\.get)?\b/,
    /SECRET_KEY\s*=\s*os\.getenv\b/,
    /SECRET_KEY\s*=\s*environ(?:\.get)?\b/,
    /SECRET_KEY\s*=\s*getenv\b/,
    /SECRET_KEY\s*=\s*config\s*\(/,
    /SECRET_KEY\s*=\s*decouple\.config\s*\(/,
    /SECRET_KEY\s*=\s*env\s*\(/,
    /SECRET_KEY\s*=\s*env\.str\s*\(/,
    /app\.config\[\s*['"]SECRET_KEY['"]\s*\]\s*=\s*os\.(?:environ|getenv)\b/,
  ];
  return envRefs.some((r) => r.test(content));
}

export async function checkPythonSecretKeyEnv(ctx: CheckContext): Promise<Finding[]> {
  const candidates: Array<{ file: ScannedFile; content: string }> = [];
  let anyPython = false;
  for (const file of ctx.files) {
    if (path.extname(file.relPath).toLowerCase() !== ".py") continue;
    anyPython = true;
    const content = await readFileSafe(file);
    if (!content) continue;
    if (isPythonSettingsLike(file.relPath, content)) {
      candidates.push({ file, content });
    }
  }
  if (!anyPython || candidates.length === 0) return [];

  let mentionsSecretKey = false;
  let envBacked = false;
  let firstMention: { file: ScannedFile; line: number } | null = null;
  for (const { file, content } of candidates) {
    const m = /\bSECRET_KEY\b/.exec(content);
    if (m) {
      mentionsSecretKey = true;
      if (!firstMention) firstMention = { file, line: findLine(content, m.index) };
    }
    if (pythonReadsSecretKeyFromEnv(content)) {
      envBacked = true;
      break;
    }
  }

  if (envBacked) return [];

  if (!mentionsSecretKey) {
    return [
      {
        checkId: "py-missing-secret-key-env",
        itemId: "secrets",
        severity: "high",
        message:
          "Detected a Django/Flask project but couldn't find SECRET_KEY anywhere in your settings. Configure it from an env var (e.g. os.environ['SECRET_KEY']) before deploying.",
        file: relPosix(candidates[0].file.relPath),
      },
    ];
  }
  return [
    {
      checkId: "py-secret-key-not-from-env",
      itemId: "secrets",
      severity: "high",
      message:
        "Django/Flask SECRET_KEY is set in source but not read from an environment variable. Pull it from os.environ / os.getenv (or python-decouple / django-environ) so the real value stays out of the repo.",
      file: firstMention ? relPosix(firstMention.file.relPath) : undefined,
      line: firstMention?.line,
    },
  ];
}

function isRailsProject(_ctx: CheckContext, files: ScannedFile[]): boolean {
  for (const f of files) {
    const rel = f.relPath.split(path.sep).join("/");
    if (/(^|\/)config\/application\.rb$/.test(rel)) return true;
    if (/(^|\/)config\/environments\/[a-z]+\.rb$/.test(rel)) return true;
  }
  return false;
}

async function gemfileMentionsRails(ctx: CheckContext): Promise<boolean> {
  const gemfile = ctx.files.find((f) => path.basename(f.relPath) === "Gemfile");
  if (!gemfile) return false;
  const content = await readFileSafe(gemfile);
  if (!content) return false;
  return /\bgem\s+['"]rails['"]/m.test(content);
}

export async function checkRubySecretKeyBaseEnv(ctx: CheckContext): Promise<Finding[]> {
  const isRails = isRailsProject(ctx, ctx.files) || (await gemfileMentionsRails(ctx));
  if (!isRails) return [];

  const configFiles: Array<{ file: ScannedFile; content: string }> = [];
  for (const file of ctx.files) {
    const rel = file.relPath.split(path.sep).join("/");
    const ext = path.extname(rel).toLowerCase();
    const inConfig = /(^|\/)config\//.test(rel);
    if (!inConfig) continue;
    if (![".rb", ".yml", ".yaml"].includes(ext)) continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    configFiles.push({ file, content });
  }
  if (configFiles.length === 0) return [];

  let mentionsSecret = false;
  let envBacked = false;
  let firstMention: { file: ScannedFile; line: number } | null = null;
  for (const { file, content } of configFiles) {
    const m = /\bsecret_key_base\b/.exec(content);
    if (m) {
      mentionsSecret = true;
      if (!firstMention) firstMention = { file, line: findLine(content, m.index) };
    }
    if (
      /ENV\[\s*['"]SECRET_KEY_BASE['"]\s*\]/.test(content) ||
      /ENV\.fetch\(\s*['"]SECRET_KEY_BASE['"]/.test(content) ||
      /Rails\.application\.credentials/.test(content)
    ) {
      envBacked = true;
    }
  }

  if (envBacked) return [];

  if (!mentionsSecret) {
    return [
      {
        checkId: "rb-missing-secret-key-base-env",
        itemId: "secrets",
        severity: "high",
        message:
          "Detected a Rails project but couldn't find secret_key_base wired up to ENV['SECRET_KEY_BASE'] or Rails.application.credentials anywhere in config/. Configure it before deploying.",
      },
    ];
  }
  return [
    {
      checkId: "rb-secret-key-base-not-from-env",
      itemId: "secrets",
      severity: "high",
      message:
        "Rails secret_key_base is referenced in config/ but not pulled from ENV['SECRET_KEY_BASE'] or Rails.application.credentials. Move the real value out of source.",
      file: firstMention ? relPosix(firstMention.file.relPath) : undefined,
      line: firstMention?.line,
    },
  ];
}
