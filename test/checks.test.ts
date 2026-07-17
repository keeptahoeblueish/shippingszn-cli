import { strict as assert } from "node:assert";
import { test } from "node:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  checkApiSpendCap,
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
  checkOtpAuthReadiness,
  checkPlaceholderContent,
  checkRateLimiting,
  checkErrorMonitoring,
  checkLegalPages,
  checkPaymentsWebhook,
  checkFileUploads,
  checkSessionCookie,
  checkUnguardedRoutes,
  checkModelFreshness,
  checkDependencyIntegrity,
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

async function makeTempCtx(
  files: Record<string, string>,
): Promise<CheckContext> {
  const tmpRoot = os.tmpdir().startsWith("/var/")
    ? "/private/tmp"
    : os.tmpdir();
  const rootDir = await fs.mkdtemp(
    path.join(tmpRoot, "shippingszn-cli-check-"),
  );
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(rootDir, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content);
  }
  return { rootDir, files: await listFiles(rootDir) };
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
    id: "llms-txt",
    fixture: "llms-txt",
    run: checkLlmsTxt,
    expectedItemId: "aeo",
    expectedSeverity: "lower",
    expectedCheckId: "missing-llms-txt",
  },
  {
    id: "pwa-manifest",
    fixture: "pwa-manifest",
    run: checkPwaManifest,
    expectedItemId: "installable-app",
    expectedSeverity: "lower",
    expectedCheckId: "missing-pwa-manifest",
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
  {
    id: "otp-auth-readiness",
    fixture: "otp-auth",
    run: checkOtpAuthReadiness,
    expectedItemId: "secure-auth",
    expectedSeverity: "high",
    expectedCheckId: "otp-phone-normalization-missing",
  },
];

test("[dangerous-patterns] shell-exec-call fires on shell execution with concatenated input", async () => {
  const ctx = await makeCtx("dangerous-patterns", "positive");
  const findings = await checkDangerousPatterns(ctx);
  const hits = findings.filter((f) => f.checkId === "shell-exec-call");
  assert.ok(
    hits.length >= 1,
    `expected at least one shell-exec-call finding, got: ${JSON.stringify(findings, null, 2)}`,
  );
  assert.equal(hits[0].severity, "high");
  assert.equal(hits[0].itemId, "common-attacks");
});

test("[dangerous-patterns] shell-exec-call does not fire on regex matcher calls", async () => {
  const ctx = await makeCtx("dangerous-patterns", "negative");
  const findings = await checkDangerousPatterns(ctx);
  const hits = findings.filter((f) => f.checkId === "shell-exec-call");
  assert.equal(
    hits.length,
    0,
    `expected no shell-exec-call findings on negative fixture, got: ${JSON.stringify(hits, null, 2)}`,
  );
});

test("[config-secret-leaks] flags public-prefixed secret assignments in .env", async () => {
  const ctx = await makeCtx("config-secret-leaks", "positive");
  const findings = await checkConfigSecretLeaks(ctx);
  const clientHits = findings.filter(
    (f) => f.checkId === "config-client-prefixed-secret",
  );
  assert.ok(
    clientHits.length >= 1,
    `expected client-prefixed-secret finding, got: ${JSON.stringify(findings, null, 2)}`,
  );
  assert.equal(clientHits[0].severity, "high");
  assert.equal(clientHits[0].itemId, "secrets");
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

test("[api-spend-cap] flags paid AI calls without nearby limits", async () => {
  const ctx = await makeTempCtx({
    "src/api.ts": `
      import OpenAI from "openai";
      const client = new OpenAI();
      export async function generate(prompt: string) {
        return client.chat.completions.create({ model: "gpt-5.4", messages: [{ role: "user", content: prompt }] });
      }
    `,
  });
  const findings = await checkApiSpendCap(ctx);
  assert.ok(findings.some((f) => f.checkId === "api-spend-cap-missing"));
  assert.equal(findings[0]!.itemId, "api-spend-cap");
});

test("[rate-limiting] flags server apps without a throttle signal", async () => {
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({ dependencies: { express: "^5.0.0" } }),
    "src/server.ts": `import express from "express"; const app = express(); app.post("/login", (_req, res) => res.json({ ok: true }));`,
  });
  const findings = await checkRateLimiting(ctx);
  assert.equal(findings[0]?.checkId, "rate-limit-missing");
  assert.equal(findings[0]?.itemId, "rate-limiting");
});

test("[error-monitoring] flags apps with no monitoring SDK or source signal", async () => {
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({ dependencies: { next: "^16.0.0" } }),
    "src/app.tsx": `export default function App() { return <main />; }`,
  });
  const findings = await checkErrorMonitoring(ctx);
  assert.equal(findings[0]?.checkId, "error-monitoring-missing");
  assert.equal(findings[0]?.itemId, "error-monitoring");
});

test("[legal-pages] flags missing terms and privacy surfaces", async () => {
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({ dependencies: { react: "^19.0.0" } }),
    "src/App.tsx": `export default function App() { return <a href="/pricing">Pricing</a>; }`,
  });
  const findings = await checkLegalPages(ctx);
  assert.deepEqual(findings.map((f) => f.checkId).sort(), [
    "legal-page-privacy-missing",
    "legal-page-terms-missing",
  ]);
  assert.ok(findings.every((f) => f.itemId === "legal-pages"));
});

test("[payments-webhook] flags Stripe webhook routes without signature verification", async () => {
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({ dependencies: { stripe: "^20.0.0" } }),
    "src/server.ts": `
      import express from "express";
      const app = express();
      app.post("/stripe/webhook", express.json(), (req, res) => {
        if (req.body.type === "checkout.session.completed") grantAccess(req.body.data.object.id);
        res.json({ received: true });
      });
    `,
  });
  const findings = await checkPaymentsWebhook(ctx);
  assert.equal(findings[0]?.checkId, "stripe-webhook-signature-missing");
  assert.equal(findings[0]?.itemId, "payments");
});

test("[payments-webhook] a webhook verifying via raw HMAC (stripe-signature + timingSafeEqual) is clean", async () => {
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({ dependencies: { stripe: "^20.0.0" } }),
    "src/server.ts": `
      import express from "express";
      import { createHmac, timingSafeEqual } from "node:crypto";
      const app = express();
      function verify(raw: string, header: string, secret: string) {
        const expected = createHmac("sha256", secret).update(raw).digest("hex");
        return timingSafeEqual(Buffer.from(expected), Buffer.from(header));
      }
      app.post("/stripe/webhook", (req, res) => {
        const sig = req.headers["stripe-signature"] as string;
        if (!verify(req.rawBody, sig, process.env.WH_SECRET!)) {
          res.status(400).end();
          return;
        }
        res.json({ received: true });
      });
    `,
  });
  const findings = await checkPaymentsWebhook(ctx);
  assert.equal(findings.length, 0);
});

test("[file-uploads] flags upload handlers without size or type guards", async () => {
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({ dependencies: { multer: "^2.0.0" } }),
    "src/upload.ts": `
      import multer from "multer";
      const upload = multer();
      app.post("/upload", upload.single("file"), handler);
    `,
  });
  const findings = await checkFileUploads(ctx);
  assert.equal(findings[0]?.checkId, "file-upload-guards-missing");
  assert.equal(findings[0]?.itemId, "file-uploads");
});

test("[session-cookie] flags session cookies missing secure flags", async () => {
  const ctx = await makeTempCtx({
    "src/server.ts": `
      app.use(session({
        secret: process.env.SESSION_SECRET,
        cookie: { secure: false }
      }));
    `,
  });
  const findings = await checkSessionCookie(ctx);
  assert.equal(findings[0]?.checkId, "session-cookie-flags-missing");
  assert.equal(findings[0]?.itemId, "session-management");
});

test("[unguarded-routes] flags admin/write routes with no auth-shaped guard", async () => {
  const ctx = await makeTempCtx({
    "src/routes.ts": `
      import { Router } from "express";
      const router = Router();
      router.delete("/admin/users/:id", async (req, res) => {
        await deleteUser(req.params.id);
        res.json({ ok: true });
      });
    `,
  });
  const findings = await checkUnguardedRoutes(ctx);
  assert.equal(findings[0]?.checkId, "unguarded-route");
  assert.equal(findings[0]?.itemId, "secure-api");
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

// ---------------------------------------------------------------------------
// Precision-fix regression tests. Each pairs (a) a genuinely-bad case that
// MUST still flag with (b) the previously-false-positive case that must be
// clean now.
// ---------------------------------------------------------------------------

// --- model-freshness: exact/dated-aware retirement matching -----------------
test("[model-freshness] a truly retired exact id still flags critical", async () => {
  const ctx = await makeTempCtx({
    "src/ai.ts": `export const MODEL = "claude-3-opus";`,
  });
  const findings = await checkModelFreshness(ctx);
  const hit = findings.find(
    (f) => f.checkId === "model-freshness" && f.severity === "critical",
  );
  assert.ok(
    hit,
    `expected a critical retired finding for claude-3-opus, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

test("[model-freshness] a current successor near a retired prefix stays clean", async () => {
  // claude-sonnet-4-5 / claude-opus-4-8 are CURRENT models whose ids begin
  // with the retired stems claude-sonnet-4 / claude-opus-4. The old prefix
  // match falsely flagged them retired (BLOCKER false positive).
  const ctx = await makeTempCtx({
    "src/ai.ts": `
      const a = { model: "claude-sonnet-4-5" };
      const b = { model: "claude-opus-4-8" };
      const c = { model: "claude-opus-4-5" };
    `,
  });
  const findings = await checkModelFreshness(ctx);
  const retired = findings.filter(
    (f) => f.checkId === "model-freshness" && f.severity === "critical",
  );
  assert.equal(
    retired.length,
    0,
    `expected no retired findings for current successors, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

test("[model-freshness] a retired base id used exactly still flags", async () => {
  const ctx = await makeTempCtx({
    "src/ai.ts": `const cfg = { model: "claude-sonnet-4" };`,
  });
  const findings = await checkModelFreshness(ctx);
  const hit = findings.find(
    (f) => f.checkId === "model-freshness" && f.severity === "critical",
  );
  assert.ok(
    hit,
    `expected claude-sonnet-4 (exact) to flag retired, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

// --- session-cookie: full options object even when a value is a call --------
test("[session-cookie] a hardened cookie whose value is a call is clean", async () => {
  // res.cookie's value is sign(token) and a flag value is isProd() — the old
  // [^)]+) match truncated at sign(token)'s ")" and reported every flag missing.
  const ctx = await makeTempCtx({
    "src/server.ts": `
      res.cookie("sid", sign(token), { httpOnly: true, secure: isProd(), sameSite: "lax" });
    `,
  });
  const findings = await checkSessionCookie(ctx);
  assert.equal(
    findings.length,
    0,
    `expected no findings on a fully-hardened cookie, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

test("[session-cookie] a cookie with a genuinely absent flag still flags", async () => {
  const ctx = await makeTempCtx({
    "src/server.ts": `
      res.cookie("sid", sign(token), { secure: isProd() });
    `,
  });
  const findings = await checkSessionCookie(ctx);
  assert.equal(findings[0]?.checkId, "session-cookie-flags-missing");
  assert.equal(findings[0]?.itemId, "session-management");
});

// --- dangerous: member exec forms + evaluate all matches --------------------
test("[dangerous-patterns] member .exec( on child_process flags", async () => {
  const ctx = await makeTempCtx({
    "src/run.ts": `
      import cp from "node:child_process";
      export function run(x: string) { return cp.exec("echo " + x); }
    `,
  });
  const findings = await checkDangerousPatterns(ctx);
  assert.ok(
    findings.some((f) => f.checkId === "shell-exec-call"),
    `expected shell-exec-call for cp.exec, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

test("[dangerous-patterns] member .execSync( flags (require form)", async () => {
  const ctx = await makeTempCtx({
    "src/run.ts": `const out = require("child_process").execSync(cmd);`,
  });
  const findings = await checkDangerousPatterns(ctx);
  assert.ok(
    findings.some((f) => f.checkId === "shell-exec-call"),
    `expected shell-exec-call for .execSync, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

test("[dangerous-patterns] regex .exec( with no child_process stays clean", async () => {
  const ctx = await makeTempCtx({
    "src/match.ts": `const re = /\\d+/g; export const m = re.exec(input);`,
  });
  const findings = await checkDangerousPatterns(ctx);
  assert.equal(
    findings.filter((f) => f.checkId === "shell-exec-call").length,
    0,
    `expected no shell-exec-call for regex.exec, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

test("[dangerous-patterns] a later unsafe dangerouslySetInnerHTML is not masked by an earlier safe one", async () => {
  const filler = "/* " + "x".repeat(1400) + " */";
  const ctx = await makeTempCtx({
    "src/view.tsx": `
      const safe = DOMPurify.sanitize(a);
      const A = \`<Comp dangerouslySetInnerHTML={{ __html: safe }} />\`;
      ${filler}
      const B = \`<Comp dangerouslySetInnerHTML={{ __html: rawUserHtml }} />\`;
    `,
  });
  const findings = await checkDangerousPatterns(ctx);
  assert.ok(
    findings.some((f) => f.checkId === "dangerously-set-inner-html"),
    `expected the later unsanitized usage to flag, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

// --- dependency-integrity: legit near-neighbors allowlisted -----------------
test("[dependency-integrity] a real typosquat still flags", async () => {
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({ dependencies: { axioss: "^1.0.0" } }),
  });
  const findings = await checkDependencyIntegrity(ctx);
  assert.ok(
    findings.some((f) => f.checkId === "dependency-integrity"),
    `expected axioss to be flagged as a typosquat of axios, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

test("[dependency-integrity] legit near-neighbors (preact, mysql) stay clean", async () => {
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({
      dependencies: { preact: "^10.0.0", mysql: "^2.18.0" },
    }),
  });
  const findings = await checkDependencyIntegrity(ctx);
  assert.equal(
    findings.length,
    0,
    `expected preact/mysql to be clean, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

// --- secrets: dedupe + PUBLIC_KEY exemption ---------------------------------
test("[secrets] a provider token in .env yields one finding, not two", async () => {
  // sk_live_… is ≥40 chars of the base64 class, so before the dedupe it was
  // flagged BOTH by checkHardcodedSecrets and by the generic config credential
  // rule. Synthetic (non-real) fixture value.
  const stripeKey = "sk_live_" + "a".repeat(40);
  const ctx = await makeTempCtx({
    ".env": `STRIPE_KEY="${stripeKey}"\n`,
  });
  const hardcoded = await checkHardcodedSecrets(ctx);
  const config = await checkConfigSecretLeaks(ctx);
  assert.equal(
    hardcoded.filter((f) => f.checkId === "secret-stripe-live-secret").length,
    1,
    "checkHardcodedSecrets should flag the Stripe key exactly once",
  );
  assert.equal(
    config.filter((f) => f.checkId === "config-hardcoded-credential").length,
    0,
    "the generic config credential rule must not double-count the same token",
  );
});

test("[secrets] a PUBLIC_KEY artifact is not flagged, a real client secret still is", async () => {
  const publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBExamplePub00";
  const ctx = await makeTempCtx({
    ".env": `PUBLIC_KEY=${publicKey}\nVITE_SUPABASE_TOKEN=abc123def456ghi\n`,
  });
  const findings = await checkConfigSecretLeaks(ctx);
  assert.equal(
    findings.length,
    1,
    `expected only the VITE_ token to flag, got: ${JSON.stringify(findings.map((f) => f.checkId))}`,
  );
  assert.equal(findings[0]?.checkId, "config-client-prefixed-secret");
  assert.ok(findings[0]?.message.includes("VITE_SUPABASE_TOKEN"));
});

// --- rate-limiting: monorepo workspace manifests are read -------------------
test("[rate-limiting] a monorepo workspace framework with no throttle flags", async () => {
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({
      name: "root",
      private: true,
      workspaces: ["artifacts/*"],
    }),
    "artifacts/api/package.json": JSON.stringify({
      dependencies: { express: "^5.0.0" },
    }),
    "artifacts/api/src/server.ts": `import express from "express"; const app = express(); app.post("/login", (_req, res) => res.json({ ok: true }));`,
  });
  const findings = await checkRateLimiting(ctx);
  assert.equal(findings[0]?.checkId, "rate-limit-missing");
  assert.equal(findings[0]?.itemId, "rate-limiting");
});

test("[rate-limiting] a monorepo workspace with a rate-limit dep stays clean", async () => {
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({ name: "root", private: true }),
    "artifacts/api/package.json": JSON.stringify({
      dependencies: { express: "^5.0.0", "express-rate-limit": "^7.0.0" },
    }),
    "artifacts/api/src/server.ts": `import express from "express"; const app = express();`,
  });
  const findings = await checkRateLimiting(ctx);
  assert.equal(
    findings.length,
    0,
    `expected clean when a workspace declares a rate-limit dep, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

// --- api-spend-cap: a per-call token cap counts as a spend guard ------------
test("[api-spend-cap] a paid-AI call with no cap keyword anywhere still flags", async () => {
  const ctx = await makeTempCtx({
    "src/ai.ts": `
      export async function ask(prompt: string) {
        const res = await fetch("https://api.openai.com/v1/chat/completions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "gpt-5.4",
            messages: [{ role: "user", content: prompt }],
          }),
        });
        return res.json();
      }
    `,
  });
  const findings = await checkApiSpendCap(ctx);
  assert.ok(
    findings.some((f) => f.checkId === "api-spend-cap-missing"),
    `expected api-spend-cap-missing when no cap is present, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

test("[api-spend-cap] a paid-AI call with a max_tokens cap nearby is clean", async () => {
  // A hard per-call max_tokens bounds spend, so it must be recognized as a
  // legitimate spend-cap signal — not a false positive.
  const ctx = await makeTempCtx({
    "src/ai.ts": `
      export async function ask(prompt: string) {
        const res = await fetch("https://api.openai.com/v1/chat/completions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "gpt-5.4",
            max_tokens: 1024,
            messages: [{ role: "user", content: prompt }],
          }),
        });
        return res.json();
      }
    `,
  });
  const findings = await checkApiSpendCap(ctx);
  assert.equal(
    findings.filter((f) => f.checkId === "api-spend-cap-missing").length,
    0,
    `expected clean when max_tokens bounds per-call spend, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

// --- monorepo manifest aggregation: workspace deps are no longer missed -----
test("[error-monitoring] a monorepo workspace app with no SDK still flags", async () => {
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({
      name: "root",
      private: true,
      workspaces: ["artifacts/*"],
    }),
    "artifacts/web/package.json": JSON.stringify({
      dependencies: { next: "^16.0.0" },
    }),
    "artifacts/web/src/app.tsx": `export default function App() { return <main />; }`,
  });
  const findings = await checkErrorMonitoring(ctx);
  assert.equal(findings[0]?.checkId, "error-monitoring-missing");
  assert.equal(findings[0]?.itemId, "error-monitoring");
});

test("[error-monitoring] a monorepo workspace declaring the SDK stays clean", async () => {
  // The SDK is declared only in the workspace manifest, and its package name
  // ("rollbar") is not itself a source signal — so the old root-only read
  // false-flagged this project. Aggregation across manifests clears it.
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({
      name: "root",
      private: true,
      workspaces: ["artifacts/*"],
    }),
    "artifacts/web/package.json": JSON.stringify({
      dependencies: { next: "^16.0.0", rollbar: "^2.26.0" },
    }),
    "artifacts/web/src/app.tsx": `export default function App() { return <main />; }`,
  });
  const findings = await checkErrorMonitoring(ctx);
  assert.equal(
    findings.length,
    0,
    `expected clean when a workspace declares an error-monitoring SDK, got: ${JSON.stringify(findings, null, 2)}`,
  );
});

test("[payments-webhook] a monorepo workspace Stripe webhook without verify flags", async () => {
  // Stripe lives in the workspace manifest, not root. The old root-only read
  // saw no stripe dep and skipped the check entirely — a false negative on a
  // genuinely-forgeable webhook. Aggregation now catches it.
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({
      name: "root",
      private: true,
      workspaces: ["artifacts/*"],
    }),
    "artifacts/api/package.json": JSON.stringify({
      dependencies: { stripe: "^20.0.0" },
    }),
    "artifacts/api/src/server.ts": `
      import express from "express";
      const app = express();
      app.post("/stripe/webhook", express.json(), (req, res) => {
        if (req.body.type === "checkout.session.completed") grantAccess(req.body.data.object.id);
        res.json({ received: true });
      });
    `,
  });
  const findings = await checkPaymentsWebhook(ctx);
  assert.equal(findings[0]?.checkId, "stripe-webhook-signature-missing");
  assert.equal(findings[0]?.itemId, "payments");
});

test("[file-uploads] a monorepo workspace upload handler without guards flags", async () => {
  // multer lives in the workspace manifest, not root. The old root-only read
  // saw no upload dep and skipped the check — a false negative on an unbounded
  // upload handler. Aggregation now catches it.
  const ctx = await makeTempCtx({
    "package.json": JSON.stringify({
      name: "root",
      private: true,
      workspaces: ["artifacts/*"],
    }),
    "artifacts/api/package.json": JSON.stringify({
      dependencies: { multer: "^2.0.0" },
    }),
    "artifacts/api/src/upload.ts": `
      import multer from "multer";
      const upload = multer();
      app.post("/upload", upload.single("file"), handler);
    `,
  });
  const findings = await checkFileUploads(ctx);
  assert.equal(findings[0]?.checkId, "file-upload-guards-missing");
  assert.equal(findings[0]?.itemId, "file-uploads");
});
