import { strict as assert } from "node:assert";
import { test } from "node:test";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
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
  checkPlaceholderContent,
  type CheckContext,
  type Finding,
} from "../src/checks.js";
import { listFiles } from "../src/scan.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(__dirname, "fixtures");

async function makeCtx(
  fixture: string,
  polarity: "positive" | "negative",
): Promise<CheckContext> {
  const rootDir = path.join(FIXTURES, fixture, polarity);
  const files = await listFiles(rootDir);
  return { rootDir, files };
}

interface CheckCase {
  id: string;
  fixture: string;
  run: (ctx: CheckContext) => Promise<Finding[]>;
  expectedItemId: string;
  expectedSeverity: Finding["severity"];
  expectedCheckIdPrefix?: string;
  expectedCheckId?: string;
}

const CASES: CheckCase[] = [
  {
    id: "hardcoded-secrets",
    fixture: "hardcoded-secrets",
    run: checkHardcodedSecrets,
    expectedItemId: "secrets",
    expectedSeverity: "critical",
    expectedCheckIdPrefix: "secret-",
  },
  {
    id: "env-committed",
    fixture: "env-committed",
    run: checkEnvCommitted,
    expectedItemId: "secrets",
    expectedSeverity: "high",
    expectedCheckId: "env-not-ignored",
  },
  {
    id: "env-example",
    fixture: "env-example",
    run: checkEnvExample,
    expectedItemId: "secrets",
    expectedSeverity: "medium",
    expectedCheckId: "missing-env-example",
  },
  {
    id: "gitignore",
    fixture: "gitignore",
    run: checkGitignore,
    expectedItemId: "github",
    expectedSeverity: "high",
    expectedCheckId: "missing-gitignore",
  },
  {
    id: "robots-txt",
    fixture: "robots-txt",
    run: checkRobotsTxt,
    expectedItemId: "seo",
    expectedSeverity: "medium",
    expectedCheckId: "missing-robots-txt",
  },
  {
    id: "sitemap-xml",
    fixture: "sitemap-xml",
    run: checkSitemapXml,
    expectedItemId: "seo",
    expectedSeverity: "medium",
    expectedCheckId: "missing-sitemap-xml",
  },
  {
    id: "favicon",
    fixture: "favicon",
    run: checkFavicon,
    expectedItemId: "launch-polish",
    expectedSeverity: "lower",
    expectedCheckId: "missing-favicon",
  },
  {
    id: "security-headers",
    fixture: "security-headers",
    run: checkSecurityHeaders,
    expectedItemId: "https-headers",
    expectedSeverity: "high",
    expectedCheckId: "missing-security-headers",
  },
  {
    id: "dangerous-patterns",
    fixture: "dangerous-patterns",
    run: checkDangerousPatterns,
    expectedItemId: "common-attacks",
    expectedSeverity: "high",
    expectedCheckId: "eval-call",
  },
  {
    id: "placeholder-content",
    fixture: "placeholder-content",
    run: checkPlaceholderContent,
    expectedItemId: "ai-audit",
    expectedSeverity: "medium",
    expectedCheckId: "placeholder-content",
  },
];

test("[config-secret-leaks] flags VITE_*_SECRET assignments in .env", async () => {
  const ctx = await makeCtx("config-secret-leaks", "positive");
  const findings = await checkConfigSecretLeaks(ctx);
  const viteHits = findings.filter(
    (f) => f.checkId === "config-vite-prefixed-secret",
  );
  assert.ok(
    viteHits.length >= 1,
    `expected VITE_-prefixed-secret finding, got: ${JSON.stringify(findings, null, 2)}`,
  );
  assert.equal(viteHits[0].severity, "high");
  assert.equal(viteHits[0].itemId, "secrets");
});

test("[config-secret-leaks] flags hex-shaped credentials in .env", async () => {
  const ctx = await makeCtx("config-secret-leaks", "positive");
  const findings = await checkConfigSecretLeaks(ctx);
  const hexHits = findings.filter(
    (f) => f.checkId === "config-hardcoded-credential",
  );
  assert.ok(
    hexHits.length >= 1,
    `expected hardcoded-credential finding, got: ${JSON.stringify(findings, null, 2)}`,
  );
  assert.equal(hexHits[0].severity, "critical");
});

test("[config-secret-leaks] does not fire on safe config values", async () => {
  const ctx = await makeCtx("config-secret-leaks", "negative");
  const findings = await checkConfigSecretLeaks(ctx);
  assert.equal(
    findings.length,
    0,
    `expected no findings on negative fixture, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

const NEW_SECRET_CHECK_IDS = [
  "secret-notion-token",
  "secret-vercel-token",
  "secret-sendgrid-api-key",
  "secret-twilio-account-sid",
  "secret-supabase-service-role-jwt",
  "secret-jwt",
];

for (const checkId of NEW_SECRET_CHECK_IDS) {
  test(`[hardcoded-secrets] ${checkId} fires exactly once on the positive fixture`, async () => {
    const ctx = await makeCtx("hardcoded-secrets", "positive");
    const findings = await checkHardcodedSecrets(ctx);
    const hits = findings.filter((f) => f.checkId === checkId);
    assert.equal(
      hits.length,
      1,
      `expected exactly one finding for ${checkId}, got ${hits.length}: ${JSON.stringify(hits, null, 2)}`,
    );
  });

  test(`[hardcoded-secrets] ${checkId} does not fire on the negative fixture`, async () => {
    const ctx = await makeCtx("hardcoded-secrets", "negative");
    const findings = await checkHardcodedSecrets(ctx);
    const hits = findings.filter((f) => f.checkId === checkId);
    assert.equal(
      hits.length,
      0,
      `expected no findings for ${checkId}, got: ${JSON.stringify(hits, null, 2)}`,
    );
  });
}

for (const c of CASES) {
  test(`[${c.id}] fires on the positive fixture with the expected severity and itemId`, async () => {
    const ctx = await makeCtx(c.fixture, "positive");
    const findings = await c.run(ctx);
    assert.ok(findings.length > 0, `expected at least one finding, got 0`);
    const match = findings.find((f) => {
      if (f.itemId !== c.expectedItemId) return false;
      if (f.severity !== c.expectedSeverity) return false;
      if (c.expectedCheckId) return f.checkId === c.expectedCheckId;
      if (c.expectedCheckIdPrefix)
        return f.checkId.startsWith(c.expectedCheckIdPrefix);
      return true;
    });
    assert.ok(
      match,
      `no finding matched expectations. Got: ${JSON.stringify(findings, null, 2)}`,
    );
  });

  test(`[${c.id}] does not fire on the negative fixture`, async () => {
    const ctx = await makeCtx(c.fixture, "negative");
    const findings = await c.run(ctx);
    const offenders = findings.filter((f) => {
      if (c.expectedCheckId) return f.checkId === c.expectedCheckId;
      if (c.expectedCheckIdPrefix)
        return f.checkId.startsWith(c.expectedCheckIdPrefix);
      return true;
    });
    assert.equal(
      offenders.length,
      0,
      `expected no findings, got: ${JSON.stringify(offenders, null, 2)}`,
    );
  });
}
