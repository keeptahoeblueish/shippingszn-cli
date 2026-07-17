/**
 * Public entry point for the scanner's check registry.
 *
 * Adding a new check: implement it in one of the per-domain modules
 * (secrets, env, headers, dangerous, language, public-assets, quality,
 * auth-readiness)
 * and append a `{ id, run }` entry to `ALL_CHECKS` below. The id is the
 * stable identifier surfaced in CLI output and is what users would put
 * in any future per-check disable list.
 */
import { checkHardcodedSecrets, checkConfigSecretLeaks } from "./secrets.js";
import { checkEnvCommitted, checkEnvExample, checkGitignore } from "./env.js";
import {
  checkRobotsTxt,
  checkSitemapXml,
  checkFavicon,
  checkLlmsTxt,
  checkPwaManifest,
} from "./public-assets.js";
import { checkSecurityHeaders } from "./headers.js";
import { checkDangerousPatterns } from "./dangerous.js";
import {
  checkLanguagePatterns,
  checkPythonSecretKeyEnv,
  checkRubySecretKeyBaseEnv,
} from "./language.js";
import { checkPlaceholderContent } from "./quality.js";
import { checkOtpAuthReadiness } from "./otp-auth.js";
import { checkApiSpendCap } from "./api-spend-cap.js";
import { checkRateLimiting } from "./rate-limiting.js";
import { checkErrorMonitoring } from "./error-monitoring.js";
import { checkLegalPages } from "./legal-pages.js";
import { checkPaymentsWebhook } from "./payments-webhook.js";
import { checkFileUploads } from "./file-uploads.js";
import { checkSessionCookie } from "./session-cookie.js";
import { checkUnguardedRoutes } from "./unguarded-routes.js";
import { checkModelFreshness } from "./model-freshness.js";
import { checkDependencyIntegrity } from "./dependency-integrity.js";

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
  checkLlmsTxt,
  checkPwaManifest,
  checkSecurityHeaders,
  checkDangerousPatterns,
  checkLanguagePatterns,
  checkPythonSecretKeyEnv,
  checkRubySecretKeyBaseEnv,
  checkPlaceholderContent,
  checkOtpAuthReadiness,
  checkApiSpendCap,
  checkRateLimiting,
  checkErrorMonitoring,
  checkLegalPages,
  checkPaymentsWebhook,
  checkFileUploads,
  checkSessionCookie,
  checkUnguardedRoutes,
  checkModelFreshness,
  checkDependencyIntegrity,
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
  { id: "llms-txt", run: checkLlmsTxt },
  { id: "pwa-manifest", run: checkPwaManifest },
  { id: "security-headers", run: checkSecurityHeaders },
  { id: "dangerous-patterns", run: checkDangerousPatterns },
  { id: "language-patterns", run: checkLanguagePatterns },
  { id: "python-secret-key-env", run: checkPythonSecretKeyEnv },
  { id: "ruby-secret-key-base-env", run: checkRubySecretKeyBaseEnv },
  { id: "placeholder-content", run: checkPlaceholderContent },
  { id: "otp-auth-readiness", run: checkOtpAuthReadiness },
  { id: "api-spend-cap", run: checkApiSpendCap },
  { id: "rate-limiting", run: checkRateLimiting },
  { id: "error-monitoring", run: checkErrorMonitoring },
  { id: "legal-pages", run: checkLegalPages },
  { id: "payments-webhook", run: checkPaymentsWebhook },
  { id: "file-uploads", run: checkFileUploads },
  { id: "session-cookie", run: checkSessionCookie },
  { id: "unguarded-routes", run: checkUnguardedRoutes },
  { id: "model-freshness", run: checkModelFreshness },
  { id: "dependency-integrity", run: checkDependencyIntegrity },
] as const;
