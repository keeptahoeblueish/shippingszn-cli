import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import * as path from "node:path";

const PROJECT_FINGERPRINT_PREFIX = "sszpf1_";

function readText(filePath: string): string | null {
  try {
    return readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

function findGitConfig(rootDir: string): string | null {
  let current = path.resolve(rootDir);
  while (true) {
    const dotGit = path.join(current, ".git");
    if (existsSync(dotGit)) {
      try {
        if (statSync(dotGit).isDirectory()) {
          return path.join(dotGit, "config");
        }
        const pointer = readText(dotGit);
        const gitDirValue = /^gitdir:\s*(.+)$/im.exec(pointer ?? "")?.[1]?.trim();
        if (!gitDirValue) return null;
        const gitDir = path.resolve(current, gitDirValue);
        const commonDirValue = readText(path.join(gitDir, "commondir"))?.trim();
        return commonDirValue
          ? path.join(path.resolve(gitDir, commonDirValue), "config")
          : path.join(gitDir, "config");
      } catch {
        return null;
      }
    }
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

function originRemote(rootDir: string): string | null {
  const configPath = findGitConfig(rootDir);
  const config = configPath ? readText(configPath) : null;
  if (!config) return null;

  let inOrigin = false;
  for (const line of config.split(/\r?\n/)) {
    const section = /^\s*\[\s*remote\s+"([^"]+)"\s*\]\s*$/i.exec(line);
    if (section) {
      inOrigin = section[1]?.toLowerCase() === "origin";
      continue;
    }
    if (/^\s*\[/.test(line)) {
      inOrigin = false;
      continue;
    }
    if (!inOrigin) continue;
    const url = /^\s*url\s*=\s*(.+?)\s*$/i.exec(line)?.[1]?.trim();
    if (!url) continue;
    return url.replace(/^"(.*)"$/, "$1");
  }
  return null;
}

function normalizeRemote(value: string): string {
  const scp = /^git@([^:]+):(.+)$/.exec(value.trim());
  const normalized = scp ? `ssh://${scp[1]}/${scp[2]}` : value.trim();
  try {
    const url = new URL(normalized);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return `${url.hostname.toLowerCase()}${url.pathname.replace(/\.git$/, "")}`;
  } catch {
    return normalized.replace(/\.git$/, "").toLowerCase();
  }
}

/**
 * Returns a stable opaque project hint without uploading a project name,
 * repository URL, local path, or source code. Paid access still requires an
 * authenticated matching purchase; this value is not a standalone secret.
 */
export function projectFingerprint(rootDir: string): string {
  const remote = originRemote(rootDir);
  const stableIdentity = remote
    ? `git\0${normalizeRemote(remote)}`
    : `local\0${path.resolve(rootDir)}`;
  const hash = createHash("sha256").update(stableIdentity).digest("hex");
  return `${PROJECT_FINGERPRINT_PREFIX}${hash}`;
}
