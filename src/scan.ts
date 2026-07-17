import { promises as fs } from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

/**
 * Ask git for the list of tracked files. Returns null when the directory
 * isn't a git work tree (or git isn't available) — callers treat that as
 * "don't know, assume tracked" so we never weaken a finding's severity
 * on a non-git project.
 */
export function getTrackedFiles(rootDir: string): Set<string> | null {
  const result = spawnSync("git", ["-C", rootDir, "ls-files", "-z"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0 || !result.stdout) return null;
  const out = new Set<string>();
  for (const rel of result.stdout.split("\0")) {
    if (rel) out.add(rel);
  }
  return out;
}

/**
 * Ask git for tracked + untracked-but-not-ignored files. Used to filter the
 * filesystem walk so that gitignored output (build artifacts, generated
 * playwright reports, local caches, .env files) doesn't generate noisy
 * false-positive findings. Returns null when the directory isn't a git
 * work tree, in which case the caller falls back to scanning everything
 * the directory walker finds.
 *
 * `-c` cached, `-o` others, `--exclude-standard` honors .gitignore +
 * .git/info/exclude + the user's global excludesfile. This is the
 * standard "git-aware" file listing approach.
 */
export function getNotIgnoredFiles(rootDir: string): Set<string> | null {
  const result = spawnSync(
    "git",
    ["-C", rootDir, "ls-files", "-co", "--exclude-standard", "-z"],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  if (result.status !== 0 || !result.stdout) return null;
  const out = new Set<string>();
  for (const rel of result.stdout.split("\0")) {
    if (rel) out.add(rel);
  }
  return out;
}

const DEFAULT_IGNORES = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  ".nuxt",
  ".turbo",
  ".cache",
  ".vercel",
  ".netlify",
  "out",
  "coverage",
  ".pnpm-store",
  ".yarn",
  ".expo",
  ".local",
  "attached_assets",
  "vendor",
]);

const TEXT_EXT = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".md",
  ".mdx",
  ".html",
  ".htm",
  ".css",
  ".scss",
  ".vue",
  ".svelte",
  ".astro",
  ".py",
  ".rb",
  ".go",
  ".rs",
  ".java",
  ".kt",
  ".swift",
  ".php",
  ".cs",
  ".env",
  ".example",
  ".sample",
  ".local",
  ".yaml",
  ".yml",
  ".toml",
  ".ini",
  ".conf",
  ".sh",
]);

const MAX_FILE_BYTES = 512 * 1024;
const MAX_DEPTH = 24;
const MAX_FILES = 50_000;

export interface ScannedFile {
  absPath: string;
  relPath: string;
  size: number;
}

export async function listFiles(rootDir: string): Promise<ScannedFile[]> {
  const out: ScannedFile[] = [];
  const visited = new Set<string>();
  const rootResolved = path.resolve(rootDir);
  // When running inside a git repo, exclude anything .gitignore'd from the
  // walk. This stops generated artifacts (e2e/playwright-report/, dist/
  // contents the user's repo gitignores explicitly, .env files in projects
  // that ignore them but live outside our DEFAULT_IGNORES) from producing
  // noisy false-positive findings. Outside a git repo we fall back to
  // walking everything DEFAULT_IGNORES doesn't already strip.
  const allowed = getNotIgnoredFiles(rootDir);

  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > MAX_DEPTH) return;
    if (out.length >= MAX_FILES) return;
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= MAX_FILES) return;
      if (entry.name.startsWith(".") && DEFAULT_IGNORES.has(entry.name))
        continue;
      if (DEFAULT_IGNORES.has(entry.name)) continue;
      const abs = path.join(dir, entry.name);
      // Refuse to follow symlinks: prevents arbitrary file reads outside the
      // target tree and protects against symlink loops causing exhaustion.
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        // Skip test fixture directories: these intentionally contain
        // bad/insecure inputs (fake secrets, missing files, etc.) used to
        // exercise the checks themselves. Counting them in a scan of a
        // consumer repo would produce noisy false positives and would also
        // break CI for this repo's own PR scan.
        if (entry.name === "fixtures") {
          const parentBase = path.basename(dir);
          if (
            parentBase === "test" ||
            parentBase === "tests" ||
            parentBase === "__tests__"
          ) {
            continue;
          }
        }
        let real: string;
        try {
          real = await fs.realpath(abs);
        } catch {
          continue;
        }
        // Stay within the original root and avoid revisiting the same
        // directory through hard-linked or aliased paths. Use path.relative
        // (separator-aware) so that a sibling like "/root-sibling" can never
        // sneak past a naive prefix check on "/root".
        const relFromRoot = path.relative(rootResolved, real);
        if (relFromRoot.startsWith("..") || path.isAbsolute(relFromRoot)) {
          continue;
        }
        if (visited.has(real)) continue;
        visited.add(real);
        await walk(abs, depth + 1);
      } else if (entry.isFile()) {
        const rel = path.relative(rootDir, abs);
        // Honor .gitignore when we have it. Comparison uses POSIX-style
        // separators because git ls-files always returns forward-slashed
        // paths even on Windows.
        if (allowed) {
          const relPosixPath = rel.split(path.sep).join("/");
          if (!allowed.has(relPosixPath)) continue;
        }
        let size = 0;
        try {
          const st = await fs.stat(abs);
          size = st.size;
        } catch {
          continue;
        }
        out.push({ absPath: abs, relPath: rel, size });
      }
    }
  }

  await walk(rootDir, 0);
  return out;
}

export function isTextFile(file: ScannedFile): boolean {
  const base = path.basename(file.relPath).toLowerCase();
  if (base.startsWith(".env")) return true;
  if (base === "dockerfile" || base === "makefile" || base === "procfile")
    return true;
  // AI-agent instruction/config files that ship as extensionless dotfiles.
  // These regularly leak internal prompts, architecture, or secrets into a
  // deploy and are worth scanning for secrets like any other text file.
  if (base === ".cursorrules" || base === ".windsurfrules") return true;
  const ext = path.extname(file.relPath).toLowerCase();
  if (TEXT_EXT.has(ext)) return true;
  return false;
}

export async function readFileSafe(file: ScannedFile): Promise<string | null> {
  if (file.size > MAX_FILE_BYTES) return null;
  try {
    return await fs.readFile(file.absPath, "utf8");
  } catch {
    return null;
  }
}

export async function fileExists(p: string): Promise<boolean> {
  try {
    await fs.stat(p);
    return true;
  } catch {
    return false;
  }
}
