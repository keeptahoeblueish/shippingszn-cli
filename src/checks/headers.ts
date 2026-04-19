import * as path from "node:path";
import { readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";

const SECURITY_HEADER_NAMES = [
  "Strict-Transport-Security",
  "Content-Security-Policy",
  "X-Content-Type-Options",
  "X-Frame-Options",
  "Referrer-Policy",
];

export async function checkSecurityHeaders(ctx: CheckContext): Promise<Finding[]> {
  const candidateFiles = ctx.files.filter((f) => {
    const rp = f.relPath.toLowerCase();
    if (rp.endsWith(".test.ts") || rp.endsWith(".spec.ts")) return false;
    return (
      rp.endsWith("vite.config.ts") ||
      rp.endsWith("vite.config.js") ||
      rp.endsWith("next.config.js") ||
      rp.endsWith("next.config.mjs") ||
      rp.endsWith("next.config.ts") ||
      rp.endsWith("nuxt.config.ts") ||
      rp.endsWith("svelte.config.js") ||
      rp.endsWith("astro.config.mjs") ||
      rp.endsWith("astro.config.ts") ||
      rp.endsWith("vercel.json") ||
      rp.endsWith("netlify.toml") ||
      /server\/index\.(t|j)s$/.test(rp) ||
      /^server\.(t|j)s$/.test(path.basename(rp)) ||
      /\bapp\.(t|j)s$/.test(rp) ||
      /\bindex\.(t|j)s$/.test(rp)
    );
  });

  if (candidateFiles.length === 0) return [];

  let foundAny = false;
  for (const file of candidateFiles) {
    const content = await readFileSafe(file);
    if (!content) continue;
    for (const h of SECURITY_HEADER_NAMES) {
      if (content.toLowerCase().includes(h.toLowerCase())) {
        foundAny = true;
        break;
      }
    }
    if (content.includes("helmet(") || content.includes('require("helmet")') || content.includes('from "helmet"')) {
      foundAny = true;
    }
    if (foundAny) break;
  }

  if (foundAny) return [];

  return [
    {
      checkId: "missing-security-headers",
      itemId: "https-headers",
      severity: "high",
      message:
        "Couldn't find any common security headers (CSP, HSTS, X-Frame-Options, etc.) or helmet() middleware in your server/host configs. Add them so the browser enforces baseline defenses.",
    },
  ];
}
