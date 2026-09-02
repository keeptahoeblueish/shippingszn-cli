import { readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";
import { findPublicDirs, isAssetEmittedDynamically } from "./helpers.js";
import { makeFinding } from "./make-finding.js";

/**
 * Parse a robots.txt body and return true if the `User-agent: *` block (or
 * any wildcard block) disallows everything (`Disallow: /`). That's a
 * declaration that the site intentionally opts out of all crawling, so we
 * shouldn't nag about a missing sitemap — sitemaps for disallowed sites are
 * contradictory.
 */
function robotsDisallowsAll(content: string): boolean {
  const lines = content.split(/\r?\n/);
  let inWildcardBlock = false;
  let sawWildcardBlock = false;
  for (const raw of lines) {
    // Strip comments and trailing whitespace.
    const line = raw.replace(/#.*$/, "").trim();
    if (line === "") {
      // Blank line ends the current block.
      inWildcardBlock = false;
      continue;
    }
    const match = line.match(/^([A-Za-z-]+)\s*:\s*(.*)$/);
    if (!match) continue;
    const directive = match[1].toLowerCase();
    const value = match[2].trim();
    if (directive === "user-agent") {
      inWildcardBlock = value === "*";
      if (inWildcardBlock) sawWildcardBlock = true;
      continue;
    }
    if (inWildcardBlock && directive === "disallow" && value === "/") {
      return true;
    }
  }
  // If the file has no wildcard block at all, conservatively assume it
  // doesn't disallow everything (some sites only target specific bots).
  void sawWildcardBlock;
  return false;
}

async function hasDisallowAllRobots(ctx: CheckContext): Promise<boolean> {
  const robotsFiles = ctx.files.filter((f) =>
    /(^|\/)robots\.txt$/i.test(f.relPath),
  );
  for (const file of robotsFiles) {
    const content = await readFileSafe(file);
    if (!content) continue;
    if (robotsDisallowsAll(content)) return true;
  }
  return false;
}

export async function checkRobotsTxt(ctx: CheckContext): Promise<Finding[]> {
  const has = ctx.files.some((f) => /(^|\/)robots\.txt$/i.test(f.relPath));
  if (has) return [];
  if (await isAssetEmittedDynamically(ctx, "robots.txt")) return [];
  const dirs = await findPublicDirs(ctx);
  if (dirs.length === 0) return [];
  return [
    makeFinding({
      checkId: "missing-robots-txt",
      itemId: "seo",
      severity: "medium",
      message: `No robots.txt found in any public directory (looked in: ${dirs.join(", ")}). Add one so search engines know what to crawl.`,
    }),
  ];
}

export async function checkSitemapXml(ctx: CheckContext): Promise<Finding[]> {
  const has = ctx.files.some((f) => /(^|\/)sitemap\.xml$/i.test(f.relPath));
  if (has) return [];
  if (await isAssetEmittedDynamically(ctx, "sitemap.xml")) return [];
  const dirs = await findPublicDirs(ctx);
  if (dirs.length === 0) return [];
  // If the project has declared itself non-indexable via robots.txt
  // (User-agent: * / Disallow: /), a sitemap would be contradictory.
  // Suppress the nag — the site owner has made a deliberate choice.
  if (await hasDisallowAllRobots(ctx)) return [];
  return [
    makeFinding({
      checkId: "missing-sitemap-xml",
      itemId: "seo",
      severity: "medium",
      message: `No sitemap.xml found in any public directory (looked in: ${dirs.join(", ")}). Add one to help search engines index your pages.`,
    }),
  ];
}

export async function checkFavicon(ctx: CheckContext): Promise<Finding[]> {
  const dirs = await findPublicDirs(ctx);
  if (dirs.length === 0) return [];
  const faviconRegex =
    /(^|\/)(favicon\.(ico|png|svg)|apple-touch-icon\.png|icon\.svg)$/i;
  const has = ctx.files.some((f) => faviconRegex.test(f.relPath));
  if (has) return [];
  return [
    makeFinding({
      checkId: "missing-favicon",
      itemId: "launch-polish",
      severity: "lower",
      message:
        "No custom favicon found in your public directory. The default browser favicon (or the framework starter one) tells visitors this is an unfinished AI-built project.",
    }),
  ];
}

export async function checkLlmsTxt(ctx: CheckContext): Promise<Finding[]> {
  const has = ctx.files.some((f) => /(^|\/)llms\.txt$/i.test(f.relPath));
  if (has) return [];
  if (await isAssetEmittedDynamically(ctx, "llms.txt")) return [];
  const dirs = await findPublicDirs(ctx);
  if (dirs.length === 0) return [];
  return [
    makeFinding({
      checkId: "missing-llms-txt",
      itemId: "aeo",
      severity: "lower",
      message: `No llms.txt found in any public directory (looked in: ${dirs.join(", ")}). Add one so AI crawlers (ChatGPT, Perplexity, Claude) can understand your site.`,
    }),
  ];
}

export async function checkPwaManifest(ctx: CheckContext): Promise<Finding[]> {
  const dirs = await findPublicDirs(ctx);
  if (dirs.length === 0) return [];
  const manifestRegex =
    /(^|\/)(manifest\.(json|webmanifest)|site\.webmanifest)$/i;
  const has = ctx.files.some((f) => manifestRegex.test(f.relPath));
  if (has) return [];
  return [
    makeFinding({
      checkId: "missing-pwa-manifest",
      itemId: "installable-app",
      severity: "lower",
      message: `No PWA manifest found in any public directory (looked in: ${dirs.join(", ")}). Add manifest.json (or site.webmanifest) so users can install your app to their phone's home screen.`,
    }),
  ];
}
