import * as path from "node:path";
import { isTextFile, readFileSafe } from "../scan.js";
import type { CheckContext, Finding } from "./types.js";
import {
  findLine,
  isScanExempt,
  lineContainsIgnoreMarker,
  relPosix,
} from "./helpers.js";

const TODO_REGEX = /\b(?:TODO|FIXME|XXX|HACK)\b/;
const PLACEHOLDER_REGEX = /\b(lorem ipsum|placeholder text|john doe|jane doe|test@example\.com)\b/i;

export async function checkPlaceholderContent(ctx: CheckContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  let todoCount = 0;
  const placeholderHits: Finding[] = [];
  for (const file of ctx.files) {
    if (!isTextFile(file)) continue;
    if (isScanExempt(file.relPath)) continue;
    const ext = path.extname(file.relPath).toLowerCase();
    if (![".ts", ".tsx", ".js", ".jsx", ".html", ".md", ".mdx"].includes(ext)) continue;
    const content = await readFileSafe(file);
    if (!content) continue;
    const todoMatch = TODO_REGEX.exec(content);
    if (todoMatch && !lineContainsIgnoreMarker(content, todoMatch.index)) todoCount++;
    const phMatch = PLACEHOLDER_REGEX.exec(content);
    if (phMatch && !lineContainsIgnoreMarker(content, phMatch.index)) {
      placeholderHits.push({
        checkId: "placeholder-content",
        itemId: "ai-audit",
        severity: "medium",
        message: `Placeholder content "${phMatch[0]}" found — make sure it isn't shown to real users.`,
        file: relPosix(file.relPath),
        line: findLine(content, phMatch.index),
      });
    }
  }
  if (todoCount > 0) {
    findings.push({
      checkId: "todo-comments",
      itemId: "ai-audit",
      severity: "lower",
      message: `Found ${todoCount} file(s) with TODO/FIXME/XXX/HACK comments. Walk through them before launch and decide which are real work.`,
    });
  }
  return findings.concat(placeholderHits.slice(0, 25));
}
