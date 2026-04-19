import type { CheckContext, Finding } from "./types.js";
import { findPublicDirs, isAssetEmittedDynamically } from "./helpers.js";

export async function checkRobotsTxt(ctx: CheckContext): Promise<Finding[]> {
  const has = ctx.files.some((f) => /(^|\/)robots\.txt$/i.test(f.relPath));
  if (has) return [];
  if (await isAssetEmittedDynamically(ctx, "robots.txt")) return [];
  const dirs = await findPublicDirs(ctx);
  if (dirs.length === 0) return [];
  return [
    {
      checkId: "missing-robots-txt",
      itemId: "seo",
      severity: "medium",
      message: `No robots.txt found in any public directory (looked in: ${dirs.join(", ")}). Add one so search engines know what to crawl.`,
    },
  ];
}

export async function checkSitemapXml(ctx: CheckContext): Promise<Finding[]> {
  const has = ctx.files.some((f) => /(^|\/)sitemap\.xml$/i.test(f.relPath));
  if (has) return [];
  if (await isAssetEmittedDynamically(ctx, "sitemap.xml")) return [];
  const dirs = await findPublicDirs(ctx);
  if (dirs.length === 0) return [];
  return [
    {
      checkId: "missing-sitemap-xml",
      itemId: "seo",
      severity: "medium",
      message: `No sitemap.xml found in any public directory (looked in: ${dirs.join(", ")}). Add one to help search engines index your pages.`,
    },
  ];
}

export async function checkFavicon(ctx: CheckContext): Promise<Finding[]> {
  const dirs = await findPublicDirs(ctx);
  if (dirs.length === 0) return [];
  const faviconRegex = /(^|\/)(favicon\.(ico|png|svg)|apple-touch-icon\.png|icon\.svg)$/i;
  const has = ctx.files.some((f) => faviconRegex.test(f.relPath));
  if (has) return [];
  return [
    {
      checkId: "missing-favicon",
      itemId: "launch-polish",
      severity: "lower",
      message:
        "No custom favicon found in your public directory. The default browser favicon (or the framework starter one) tells visitors this is a vibe-coded project.",
    },
  ];
}
