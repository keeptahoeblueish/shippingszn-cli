/**
 * Public entry point for the scanner's check registry.
 *
 * Adding a new check: implement it in one of the per-domain modules
 * (secrets, env, headers, dangerous, language, public-assets, quality)
 * and append a `{ id, run }` entry to `ALL_CHECKS` below. The id is the
 * stable identifier surfaced in CLI output and is what users would put
 * in any future per-check disable list.
 */
import { checkHardcodedSecrets, checkConfigSecretLeaks } from "./secrets.js";
import { checkEnvCommitted, checkEnvExample, checkGitignore } from "./env.js";
import { checkRobotsTxt, checkSitemapXml, checkFavicon } from "./public-assets.js";
import { checkSecurityHeaders } from "./headers.js";
import { checkDangerousPatterns } from "./dangerous.js";
import {
  checkLanguagePatterns,
  checkPythonSecretKeyEnv,
  checkRubySecretKeyBaseEnv,
} from "./language.js";
import { checkPlaceholderContent } from "./quality.js";

export * from "./types.js";
export {
  checkHardcodedSecrets,
  checkConfigSecretLeaks,
  checkEnvCommitted,
  checkEnvExample,
  checkGitignore,
  checkRobotsTxt,
  checkSitemapXml,
  checkFavicon,
  checkSecurityHeaders,
  checkDangerousPatterns,
  checkLanguagePatterns,
  checkPythonSecretKeyEnv,
  checkRubySecretKeyBaseEnv,
  checkPlaceholderContent,
};

export const ALL_CHECKS = [
  { id: "hardcoded-secrets", run: checkHardcodedSecrets },
  { id: "config-secret-leaks", run: checkConfigSecretLeaks },
  { id: "env-committed", run: checkEnvCommitted },
  { id: "env-example", run: checkEnvExample },
  { id: "gitignore", run: checkGitignore },
  { id: "robots-txt", run: checkRobotsTxt },
  { id: "sitemap-xml", run: checkSitemapXml },
  { id: "favicon", run: checkFavicon },
  { id: "security-headers", run: checkSecurityHeaders },
  { id: "dangerous-patterns", run: checkDangerousPatterns },
  { id: "language-patterns", run: checkLanguagePatterns },
  { id: "python-secret-key-env", run: checkPythonSecretKeyEnv },
  { id: "ruby-secret-key-base-env", run: checkRubySecretKeyBaseEnv },
  { id: "placeholder-content", run: checkPlaceholderContent },
] as const;
