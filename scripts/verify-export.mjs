#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  accessSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST_NAME = "export-manifest.json";
const MANIFEST_PATH = join(ROOT, MANIFEST_NAME);
const PUBLIC_TREE_EXCLUDED_ROOT_ENTRIES = new Set([
  ".git",
  "dist",
  "node_modules",
]);
const SYNTHETIC_ENV_FIXTURES = new Set([
  "test/fixtures/config-secret-leaks/negative/.env.local",
  "test/fixtures/env-committed/positive/.env",
  "test/fixtures/env-example/negative/.env.example",
  "test/fixtures/env-example/positive/.env",
]);
const SYNTHETIC_SECRET_FILE_HASHES = new Map([
  [
    "test/fixtures/hardcoded-secrets/positive/jwt.ts",
    "5fec79062cc115d740aa54132bf8ab080e246deed3904f398be33bf589604866",
  ],
  [
    "test/fixtures/hardcoded-secrets/positive/notion.ts",
    "8d02b81e4648a8d38729e104ee3ddfc89d39cc8853672d02c7c61d0eb04a7bdb",
  ],
  [
    "test/fixtures/hardcoded-secrets/positive/supabase.ts",
    "dd7c90de0a7a9441cd9d5520c2a273e46262e87d99d2329b510f91aa4122e9de",
  ],
  [
    "test/fixtures/hardcoded-secrets/positive/twilio.ts",
    "175d96e50a97169b0a51ba8de87c3539ff89a50f29e66cfa5fae77e1bfb78997",
  ],
  [
    "test/fixtures/hardcoded-secrets/positive/vercel.ts",
    "0cb9a387fde7899c3309cb4b43986eec8d8ca21bd03bca1482161a0e98a1f9c4",
  ],
]);
const SECRET_VALUE_PATTERNS = [
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/,
  /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
  /\bsk_live_[A-Za-z0-9]{16,}\b/,
  /\bpk_live_[A-Za-z0-9]{16,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bAIza[0-9A-Za-z_-]{35}\b/,
  /\bghp_[A-Za-z0-9]{30,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
  /\bsecret_[A-Za-z0-9]{43}\b/,
  /\b(?:VERCEL_TOKEN|vercel_token|vercelToken)\b\s*[:=]\s*['"]?[A-Za-z0-9]{24}['"]?/,
  /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
  /\bAC[a-f0-9]{32}\b/,
  /\bsk_test_[A-Za-z0-9]{16,}\b/,
  /\brk_live_[A-Za-z0-9]{16,}\b/,
  /\bwhsec_[A-Za-z0-9]{16,}\b/,
  /\bre_[A-Za-z0-9]{16,}\b/,
  /\bsb_secret_[A-Za-z0-9_-]{20,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{22,}\b/,
  /\bgh[ousr]_[A-Za-z0-9]{30,}\b/,
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[^\s:@/]+:[^\s@/]{4,}@(?!localhost|host\b|hostname|your[-_]|example|changeme|127\.0\.0\.1|0\.0\.0\.0)[a-z0-9.-]+\.[a-z]{2,}/i,
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
];
const EXPECTED_PACKAGE_FILES = [
  "LICENSE",
  "README.md",
  "dist/index.js",
  "package.json",
];
const EXPECTED_DEV_DEPENDENCIES = {
  "@types/node": "20.19.28",
  esbuild: "0.28.1",
  tsx: "4.21.0",
  typescript: "5.9.3",
};
const EXPECTED_SCRIPTS = {
  build: "node ./build.mjs",
  dev: "tsx ./src/index.ts",
  start: "node ./dist/index.js",
  test: "node scripts/test.mjs",
  typecheck: "tsc -p tsconfig.json --noEmit",
  clean: "rm -rf dist",
  "verify:export": "node scripts/verify-export.mjs",
  "verify:artifact": "node scripts/verify-export.mjs --artifact",
  "verify:release":
    "npm run verify:export && npm run typecheck && npm test && npm run build && node scripts/verify-export.mjs --release",
  prepublishOnly:
    "npm run verify:export && npm run clean && npm run typecheck && npm test && npm run build && node scripts/verify-export.mjs --release",
};

function fail(message) {
  throw new Error(`[verify-export] ${message}`);
}

function normalizePath(path) {
  return path.split(sep).join("/");
}

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseMode(args) {
  let artifact = false;
  let release = false;
  for (const arg of args) {
    if (arg === "--artifact") artifact = true;
    else if (arg === "--release") {
      artifact = true;
      release = true;
    } else fail(`unknown option: ${arg}`);
  }
  return { artifact, release };
}

function decodeManagedText(path, bytes) {
  if (bytes.includes(0)) {
    fail(`binary or NUL-containing file is not allowed: ${path}`);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`file is not valid UTF-8 text: ${path}`);
  }
}

function walkPublicSourceFiles(directory = ROOT) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = join(directory, entry.name);
    const path = normalizePath(relative(ROOT, absolute));
    if (directory === ROOT && entry.name === ".git") continue;
    if (
      directory === ROOT &&
      PUBLIC_TREE_EXCLUDED_ROOT_ENTRIES.has(entry.name)
    ) {
      const stat = lstatSync(absolute);
      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        fail(`excluded path must be a real directory: ${path}`);
      }
      continue;
    }
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) fail(`public tree contains a symlink: ${path}`);
    if (stat.isDirectory()) files.push(...walkPublicSourceFiles(absolute));
    else if (stat.isFile()) {
      if (stat.nlink > 1) {
        fail(`public tree contains a multiply linked file: ${path}`);
      }
      files.push(path);
    } else fail(`public tree contains a non-file entry: ${path}`);
  }
  return files;
}

function collectStrings(value, output = []) {
  if (typeof value === "string") output.push(value);
  else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, output);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) collectStrings(item, output);
  }
  return output;
}

function assertExactRecord(actual, expected, label) {
  if (!actual || typeof actual !== "object" || Array.isArray(actual)) {
    fail(`${label} must be an object`);
  }
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    fail(`${label} keys do not match the public package contract`);
  }
  for (const key of expectedKeys) {
    if (actual[key] !== expected[key]) {
      fail(`${label}.${key} does not match the public package contract`);
    }
  }
}

function artifactEnvironment() {
  return {
    ...process.env,
    NPM_CONFIG_CACHE:
      process.env.NPM_CONFIG_CACHE ??
      join(tmpdir(), "shippingszn-public-cli-npm-cache"),
    NPM_CONFIG_FUND: "false",
    NPM_CONFIG_UPDATE_NOTIFIER: "false",
  };
}

function verifyArtifact(packageJson) {
  const executable = join(ROOT, "dist/index.js");
  if (!existsSync(executable)) fail("dist/index.js is missing after build");
  accessSync(executable, constants.X_OK);
  if ((statSync(executable).mode & 0o111) === 0) {
    fail("dist/index.js is not executable");
  }

  const temporaryRoot = mkdtempSync(join(tmpdir(), "shippingszn-pack-"));
  try {
    const packed = JSON.parse(
      execFileSync(
        "npm",
        [
          "pack",
          "--json",
          "--ignore-scripts",
          "--pack-destination",
          temporaryRoot,
        ],
        {
          cwd: ROOT,
          encoding: "utf8",
          env: artifactEnvironment(),
        },
      ),
    );
    const packageFiles = packed?.[0]?.files?.map((entry) => entry.path).sort();
    if (
      JSON.stringify(packageFiles) !== JSON.stringify(EXPECTED_PACKAGE_FILES)
    ) {
      fail(`unexpected npm package contents: ${JSON.stringify(packageFiles)}`);
    }
    const filename = packed?.[0]?.filename;
    if (typeof filename !== "string" || filename.length === 0) {
      fail("npm pack did not report a tarball filename");
    }

    const installRoot = join(temporaryRoot, "installed");
    mkdirSync(installRoot);
    execFileSync(
      "npm",
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--prefix",
        installRoot,
        join(temporaryRoot, filename),
      ],
      {
        cwd: temporaryRoot,
        encoding: "utf8",
        env: artifactEnvironment(),
      },
    );
    const installedBin = join(
      installRoot,
      "node_modules",
      ".bin",
      "shippingszn",
    );
    const installedVersion = execFileSync(installedBin, ["--version"], {
      cwd: installRoot,
      encoding: "utf8",
    }).trim();
    if (installedVersion !== packageJson.version) {
      fail("installed tarball CLI version does not match package.json");
    }
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

const mode = parseMode(process.argv.slice(2));
if (!existsSync(MANIFEST_PATH)) fail(`${MANIFEST_NAME} is missing`);

const manifest = JSON.parse(readFileSync(MANIFEST_PATH, "utf8"));
if (manifest.schemaVersion !== 1) fail("unsupported manifest schemaVersion");
if (!/^[0-9a-f]{40}$/.test(manifest.sourceCommit ?? "")) {
  fail("manifest sourceCommit must be a full Git commit SHA");
}
if (!new Set(["clean", "dirty"]).has(manifest.sourceTreeState)) {
  fail("manifest sourceTreeState must be clean or dirty");
}
if (mode.release && manifest.sourceTreeState !== "clean") {
  fail("release requires an export generated from a clean source tree");
}
if (!Array.isArray(manifest.files) || manifest.files.length === 0) {
  fail("manifest has no managed file entries");
}

const manifestPaths = manifest.files.map((entry) => entry.path);
const sortedManifestPaths = [...manifestPaths].sort();
if (new Set(manifestPaths).size !== manifestPaths.length) {
  fail("manifest contains duplicate paths");
}
if (JSON.stringify(manifestPaths) !== JSON.stringify(sortedManifestPaths)) {
  fail("manifest paths are not sorted");
}

for (const entry of manifest.files) {
  if (
    typeof entry.path !== "string" ||
    entry.path !== normalizePath(entry.path) ||
    entry.path.startsWith("/") ||
    entry.path.startsWith("../") ||
    entry.path.includes("/../") ||
    !/^[0-9a-f]{64}$/.test(entry.sha256 ?? "")
  ) {
    fail("manifest contains an invalid path or SHA-256 entry");
  }
  const absolute = resolve(ROOT, entry.path);
  if (!absolute.startsWith(`${ROOT}${sep}`)) {
    fail(`manifest path escapes the repository: ${entry.path}`);
  }
  if (!existsSync(absolute)) fail(`managed file is missing: ${entry.path}`);
  const stat = lstatSync(absolute);
  if (!stat.isFile()) {
    fail(`managed path is not a regular file: ${entry.path}`);
  }
  if (stat.nlink > 1) {
    fail(`managed path is multiply linked: ${entry.path}`);
  }
  const actual = hash(readFileSync(absolute));
  if (actual !== entry.sha256) {
    fail(`managed file hash mismatch: ${entry.path}`);
  }
}

const actualPublicPaths = walkPublicSourceFiles().sort();
const expectedPublicPaths = [...manifestPaths, MANIFEST_NAME].sort();
if (JSON.stringify(actualPublicPaths) !== JSON.stringify(expectedPublicPaths)) {
  const extra = actualPublicPaths.filter(
    (path) => !expectedPublicPaths.includes(path),
  );
  const missing = expectedPublicPaths.filter(
    (path) => !actualPublicPaths.includes(path),
  );
  fail(
    `public source tree drift (extra=${extra.join(",") || "none"}; missing=${missing.join(",") || "none"})`,
  );
}

for (const [path, expectedHash] of SYNTHETIC_SECRET_FILE_HASHES) {
  if (!manifestPaths.includes(path)) {
    fail(`pinned synthetic-secret fixture is missing: ${path}`);
  }
  if (hash(readFileSync(join(ROOT, path))) !== expectedHash) {
    fail(`pinned synthetic-secret fixture changed unexpectedly: ${path}`);
  }
}

const packageJson = JSON.parse(
  readFileSync(join(ROOT, "package.json"), "utf8"),
);
const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8"));
if (
  packageJson.version !== manifest.packageVersion ||
  lock.version !== manifest.packageVersion ||
  lock.packages?.[""]?.version !== manifest.packageVersion
) {
  fail("package.json, package-lock.json, and manifest versions do not match");
}
if (packageJson.name !== "shippingszn") fail("unexpected public package name");
if (packageJson.engines?.node !== ">=20") {
  fail("public runtime must advertise Node >=20");
}
if (
  JSON.stringify(packageJson.bin) !==
  JSON.stringify({ shippingszn: "dist/index.js" })
) {
  fail("public package bin mapping must point only to dist/index.js");
}
if (
  JSON.stringify(packageJson.files) !==
  JSON.stringify(["dist", "README.md", "LICENSE"])
) {
  fail("public package files allowlist changed");
}
assertExactRecord(
  packageJson.devDependencies,
  EXPECTED_DEV_DEPENDENCIES,
  "devDependencies",
);
assertExactRecord(
  lock.packages?.[""]?.devDependencies,
  EXPECTED_DEV_DEPENDENCIES,
  "lockfile root devDependencies",
);
assertExactRecord(packageJson.scripts, EXPECTED_SCRIPTS, "scripts");
assertExactRecord(
  packageJson.publishConfig,
  {
    access: "public",
    registry: "https://registry.npmjs.org/",
  },
  "publishConfig",
);
if (
  packageJson.dependencies &&
  Object.keys(packageJson.dependencies).length > 0
) {
  fail("public package must not rely on unbundled runtime dependencies");
}
if (
  packageJson.repository?.url !==
    "git+https://origin.cursor.com/novus/shippingszn-cli.git" ||
  "bugs" in packageJson
) {
  fail("package metadata does not point exclusively at Cursor Origin");
}

for (const value of collectStrings(packageJson)) {
  if (value.includes("workspace:") || value.includes("catalog:")) {
    fail("package.json contains a workspace or catalog dependency value");
  }
}

for (const path of manifestPaths) {
  const base = path.split("/").at(-1) ?? "";
  if (base.startsWith(".env") && !SYNTHETIC_ENV_FIXTURES.has(path)) {
    fail(`unexpected dotenv file in public export: ${path}`);
  }
  const bytes = readFileSync(join(ROOT, path));
  const text = decodeManagedText(path, bytes);
  if (
    /\/Users\/[A-Za-z0-9._-]+\//.test(text) ||
    /\/home\/[A-Za-z0-9._-]+\//.test(text)
  ) {
    fail(`absolute workstation path found in ${path}`);
  }
  if (
    /(?:from\s*|import\s*\()\s*["']@workspace\//.test(text) ||
    /import\s+["']@workspace\//.test(text)
  ) {
    fail(`workspace import remains in ${path}`);
  }
  const pinnedSyntheticHash = SYNTHETIC_SECRET_FILE_HASHES.get(path);
  for (const pattern of SECRET_VALUE_PATTERNS) {
    if (pattern.test(text) && hash(bytes) !== pinnedSyntheticHash) {
      fail(`secret-shaped value found in ${path}`);
    }
  }
}

for (const path of manifestPaths) {
  if (
    /^src\/vendor\/checklist-data\/(?:items-[^/]+|metadata|index)\.ts$/.test(
      path,
    )
  ) {
    fail(`forbidden rich checklist source found in export: ${path}`);
  }
}
const publicChecklist = readFileSync(
  join(ROOT, "src/vendor/checklist-data/public.ts"),
  "utf8",
);
if (
  /\b(?:what|why|steps|redFlags|prompt|references|cliPrompt|whyManual)\s*[?:]?:/.test(
    publicChecklist,
  )
) {
  fail("public checklist metadata contains a paid or private checklist field");
}

if (
  manifestPaths.some((path) => path.startsWith(".github/")) ||
  existsSync(join(ROOT, ".github/workflows/ci.yml")) ||
  existsSync(join(ROOT, ".github/workflows/release-cli.yml"))
) {
  fail("public repository contains retired forge automation");
}

if (mode.artifact) verifyArtifact(packageJson);

console.log(
  `[verify-export] ${manifest.files.length} managed files verified${mode.artifact ? "; installed release artifact verified" : ""}${mode.release ? "; clean release provenance verified" : ""}`,
);
