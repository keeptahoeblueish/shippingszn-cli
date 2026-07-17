import { strict as assert } from "node:assert";
import { test } from "node:test";
import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { CHECKLIST_PUBLIC as CHECKLIST } from "../src/vendor/checklist-data/public.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_ROOT = path.resolve(__dirname, "..");
const TSX_BIN = path.join(CLI_ROOT, "node_modules", ".bin", "tsx");
const ENTRY = path.join(CLI_ROOT, "src", "index.ts");
const FIXTURES = path.join(__dirname, "fixtures", "cli-exit");

// A config home that already carries the first-run telemetry marker, so the
// once-per-machine disclosure stays silent for the default CLI runs below.
// Tests that exercise the disclosure pass their own fresh SHIPPINGSZN_CONFIG_HOME.
const SEEN_CONFIG_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "ssz-seen-"));
fs.mkdirSync(path.join(SEEN_CONFIG_HOME, "shippingszn"), { recursive: true });
fs.writeFileSync(path.join(SEEN_CONFIG_HOME, "shippingszn", "seen"), "seen\n");

function runCli(
  fixture: string,
  extraArgs: string[] = [],
  env: Record<string, string> = {},
) {
  const res = spawnSync(
    TSX_BIN,
    [ENTRY, path.join(FIXTURES, fixture), "--json", "--no-color", ...extraArgs],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_ACTIONS: "",
        SHIPPINGSZN_BASE_URL: "http://127.0.0.1:9",
        SHIPPINGSZN_CONFIG_HOME: SEEN_CONFIG_HOME,
        ...env,
      },
    },
  );
  return res;
}

function runHumanCli(
  fixture: string,
  extraArgs: string[] = [],
  env: Record<string, string> = {},
) {
  const res = spawnSync(
    TSX_BIN,
    [ENTRY, path.join(FIXTURES, fixture), "--no-color", ...extraArgs],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_ACTIONS: "",
        SHIPPINGSZN_BASE_URL: "http://127.0.0.1:9",
        SHIPPINGSZN_CONFIG_HOME: SEEN_CONFIG_HOME,
        ...env,
      },
    },
  );
  return res;
}

function runRawCli(args: string[]) {
  return spawnSync(TSX_BIN, [ENTRY, ...args], {
    encoding: "utf8",
    env: {
      ...process.env,
      GITHUB_ACTIONS: "",
      SHIPPINGSZN_CONFIG_HOME: SEEN_CONFIG_HOME,
    },
  });
}

interface ScoreOnlyReport {
  score: number;
  band: "no_go" | "fix_first" | "verify_before_launch" | "launchable";
  counts: {
    critical: number;
    high: number;
    medium: number;
    lower: number;
  };
  filesScanned: number;
  coverage: {
    checksCompleted: number;
    checklistAreas: number;
  };
  scannerVersion: string;
  findings: Array<{
    checkId: string;
    itemId: string;
    severity: "critical" | "high" | "medium" | "lower";
    itemTitle: string;
    message: string;
    file?: string;
    line?: number;
    permalink: string;
  }>;
  unlockUrl: string;
  wall: {
    status: "published" | "skipped" | "failed" | "disabled";
    url?: string;
    error?: string;
  };
  scanHandoff: {
    status: "uploaded" | "skipped" | "failed";
    resultId?: string;
    unlockUrl?: string;
    error?: string;
  };
}

function parseReport(res: ReturnType<typeof runCli>): ScoreOnlyReport {
  return JSON.parse(res.stdout);
}

test("CLI rejects malformed options instead of scanning an unintended target", () => {
  const cases = [
    { args: ["--cwd"], message: /--cwd requires a value/ },
    { args: ["--base-url", "--json"], message: /--base-url requires a value/ },
    { args: ["--unknown"], message: /Unknown option/ },
    {
      args: ["--base-url", "file:///tmp", "--help"],
      message: /must use http:\/\/ or https:\/\//,
    },
    {
      args: [FIXTURES, path.join(FIXTURES, "clean"), "--help"],
      message: /exactly one scan target/,
    },
  ];

  for (const { args, message } of cases) {
    const res = runRawCli(args);
    assert.equal(res.status, 2, `args=${JSON.stringify(args)}\n${res.stderr}`);
    assert.match(res.stderr, message);
  }
});

test("CLI rejects a nonexistent scan target instead of reporting a partial score", () => {
  const missing = path.join(os.tmpdir(), `shippingszn-missing-${Date.now()}`);
  const res = runRawCli([missing, "--json", "--no-telemetry"]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /Scan target does not exist/);
  assert.equal(res.stdout, "");
});

test("CLI canonicalizes trailing slashes in generated product links", () => {
  const res = runCli("clean", [
    "--no-telemetry",
    "--base-url",
    "https://example.test///",
  ]);
  assert.equal(res.status, 0, res.stderr);
  const report = parseReport(res);
  assert.equal(report.unlockUrl, "https://example.test/fix-kit");
  assert.ok(
    report.findings.every((finding) =>
      finding.permalink.startsWith("https://example.test/i/"),
    ),
  );
});

async function startProofServer() {
  const script = `
    const http = require("node:http");
    let count = 0;
    let last = null;
    let wallCount = 0;
    let wallLast = null;
    const server = http.createServer((req, res) => {
      if (req.method === "GET" && req.url === "/_count") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ count }));
        return;
      }
      if (req.method === "GET" && req.url === "/_last") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(last));
        return;
      }
      if (req.method === "GET" && req.url === "/_wall_count") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ count: wallCount }));
        return;
      }
      if (req.method === "GET" && req.url === "/_wall_last") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(wallLast));
        return;
      }
      if (req.method === "POST" && req.url === "/api/scan-results") {
        count += 1;
        let body = "";
        req.setEncoding("utf8");
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", () => {
          last = JSON.parse(body);
          res.statusCode = 201;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({
            id: "00000000-0000-4000-8000-000000000123",
            ...last
          }));
        });
        return;
      }
      if (req.method === "POST" && req.url === "/api/wall") {
        wallCount += 1;
        let body = "";
        req.setEncoding("utf8");
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", () => {
          wallLast = JSON.parse(body);
          res.statusCode = 201;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ id: "wall-1" }));
        });
        return;
      }
      res.statusCode = 404;
      res.end("not found");
    });
    server.listen(0, "127.0.0.1", () => {
      process.stdout.write(JSON.stringify({ port: server.address().port }) + "\\n");
    });
  `;

  const child = spawn(process.execPath, ["-e", script], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const port = await new Promise<number>((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      reject(new Error(`proof server did not start: ${stderr}`));
    }, 5000);
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
      const line = stdout.split("\n")[0];
      if (line) {
        clearTimeout(timer);
        resolve(JSON.parse(line).port);
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("error", reject);
  });
  const baseUrl = `http://127.0.0.1:${port}`;
  return {
    baseUrl,
    async json(pathname: string) {
      return (await (await fetch(`${baseUrl}${pathname}`)).json()) as unknown;
    },
    close() {
      child.kill();
    },
  };
}

test("CLI exits non-zero when a critical finding is present", () => {
  const res = runCli("critical");
  assert.equal(res.status, 1, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
  const report = parseReport(res);
  assert.ok(
    report.counts.critical > 0,
    `expected at least one critical finding, got counts=${JSON.stringify(report.counts)}`,
  );
  assert.equal(report.band, "no_go");
  assert.equal(report.unlockUrl, "http://127.0.0.1:9/fix-kit");
  assert.equal(report.scanHandoff.status, "failed");
  assert.equal(typeof report.score, "number");
  assert.ok(report.score >= 0 && report.score <= 100);
  assert.equal(report.coverage.checklistAreas, CHECKLIST.length);
  assert.ok(report.coverage.checksCompleted >= 1);
  assert.equal(typeof report.scannerVersion, "string");
  assert.equal(typeof report.filesScanned, "number");
  // Free JSON now ships the full diagnosis: every finding with file:line + message.
  assert.ok(Array.isArray(report.findings));
  assert.ok(
    report.findings.length > 0,
    "expected findings array to be present in default JSON output",
  );
  const critical = report.findings.find((f) => f.severity === "critical");
  assert.ok(critical, "expected a critical finding in the findings array");
  assert.equal(typeof critical.itemTitle, "string");
  assert.equal(typeof critical.message, "string");
  assert.equal(critical.file, "leak.ts");
  assert.equal(
    (report as unknown as { detailsLocked?: unknown }).detailsLocked,
    undefined,
    "detailsLocked gating should be dropped from the diagnosis JSON",
  );
  assert.ok(
    (report as unknown as { launchReadiness?: unknown }).launchReadiness ===
      undefined,
  );
});

test("CLI exits 0 when no critical findings are present", () => {
  const res = runCli("clean");
  assert.equal(res.status, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
  const report = parseReport(res);
  assert.equal(report.counts.critical, 0);
  assert.equal(report.counts.high, 0);
  assert.equal(report.band, "launchable");
  assert.ok(Array.isArray(report.findings));
  assert.equal(report.unlockUrl, "http://127.0.0.1:9/fix-kit");
  assert.equal(report.scanHandoff.status, "failed");
  assert.ok(
    report.score >= 90,
    `expected score >=90 for clean fixture, got ${report.score}`,
  );
});

test("CLI exits 0 when only non-critical findings are present", () => {
  const res = runCli("non-critical");
  assert.equal(res.status, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
  const report = parseReport(res);
  assert.equal(report.counts.critical, 0, "expected zero critical findings");
  const nonCritical =
    report.counts.high + report.counts.medium + report.counts.lower;
  assert.ok(
    nonCritical > 0,
    `expected at least one non-critical finding, got counts ${JSON.stringify(report.counts)}`,
  );
  // Findings are free — the array is present and carries no critical severity.
  assert.ok(report.findings.length > 0);
  assert.equal(
    report.findings.filter((f) => f.severity === "critical").length,
    0,
  );
  assert.equal(report.unlockUrl, "http://127.0.0.1:9/fix-kit");
  assert.equal(report.scanHandoff.status, "failed");
  assert.equal(report.band, "fix_first");
  assert.ok(
    report.score >= 60 && report.score <= 79,
    `expected no-critical findings to stay in the fix-first score band, got ${report.score}`,
  );
});

test("human CLI output prints every finding and the remediation CTA", async () => {
  const server = await startProofServer();
  try {
    const res = runHumanCli("non-critical", ["--base-url", server.baseUrl]);
    assert.equal(res.status, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
    assert.match(res.stdout, /Verdict:\s+FIX FIRST/);
    assert.match(res.stdout, /Readiness Score:\s+\d+\/100/);
    assert.match(res.stdout, /Higher is better\./);
    assert.doesNotMatch(res.stdout, /FIX NOW/);
    assert.match(res.stdout, /Findings detected:/);
    // The full diagnosis is now printed: a grouped findings block with the
    // per-severity headers and the actual checklist-item titles + messages.
    assert.match(res.stdout, /\nFindings:/);
    assert.match(res.stdout, /HIGH \(1\)/);
    assert.match(res.stdout, /MEDIUM \(2\)/);
    assert.match(res.stdout, /LOWER \(3\)/);
    assert.match(res.stdout, /Connect to GitHub for backups and history/);
    assert.match(res.stdout, /No \.gitignore at the project root/);
    // Reframed CTA: findings are free, the Kit is the fix layer.
    assert.match(res.stdout, /The findings above are free\./);
    assert.match(res.stdout, /Per-finding fix instructions/);
    assert.match(res.stdout, /58-item launch workbook/);
    assert.match(res.stdout, /Get the fixes:/);
    assert.match(res.stdout, /\/fix-kit\?scanResultId=/);
    // Old paywall framing must be gone.
    assert.doesNotMatch(res.stdout, /Full findings are locked/);
    assert.doesNotMatch(res.stdout, /Unlock this exact scan/);
  } finally {
    server.close();
  }
});

test("critical human output prints file:line for located findings", () => {
  const res = runHumanCli("critical", ["--no-telemetry"]);
  assert.equal(res.status, 1, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
  assert.match(res.stdout, /Verdict:\s+FIX NOW/);
  assert.match(res.stdout, /\nFindings:/);
  assert.match(res.stdout, /CRITICAL \(\d+\)/);
  assert.match(res.stdout, /leak\.ts:1/);
});

test("CLI creates a scan-specific Fix Kit handoff by default", async () => {
  const server = await startProofServer();
  try {
    const res = runCli("clean", ["--base-url", server.baseUrl]);
    assert.equal(res.status, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
    const report = parseReport(res);
    assert.equal(report.scanHandoff.status, "uploaded");
    assert.equal(
      report.scanHandoff.resultId,
      "00000000-0000-4000-8000-000000000123",
    );
    assert.equal(
      report.unlockUrl,
      `${server.baseUrl}/fix-kit?scanResultId=00000000-0000-4000-8000-000000000123`,
    );
    const state = (await server.json("/_count")) as { count: number };
    assert.equal(state.count, 1);
  } finally {
    server.close();
  }
});

test("CLI publishes anonymous Wall stats by default", async () => {
  const server = await startProofServer();
  try {
    const res = runCli("non-critical", ["--base-url", server.baseUrl], {});
    assert.equal(res.status, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
    const report = parseReport(res);
    assert.equal(report.scanHandoff.status, "uploaded");
    assert.equal(report.wall.status, "published");
    assert.equal(report.wall.url, `${server.baseUrl}/wall`);

    const proofCount = (await server.json("/_count")) as { count: number };
    assert.equal(proofCount.count, 1);

    const wallCount = (await server.json("/_wall_count")) as { count: number };
    assert.equal(wallCount.count, 1);
    const wallPayload = (await server.json("/_wall_last")) as {
      source: string;
      scanResultId?: string;
      score: number;
      label: string;
      filesScanned: number;
      findingsCritical: number;
      findingsHigh: number;
      findingsMedium: number;
      findingsLower: number;
      scannerVersion: string;
    };
    assert.equal(wallPayload.source, "cli");
    assert.equal(
      wallPayload.scanResultId,
      "00000000-0000-4000-8000-000000000123",
    );
    assert.equal(wallPayload.score, report.score);
    assert.equal(typeof wallPayload.label, "string");
    assert.equal(wallPayload.filesScanned, report.filesScanned);
    assert.equal(wallPayload.findingsCritical, report.counts.critical);
    assert.equal(wallPayload.findingsHigh, report.counts.high);
    assert.equal(wallPayload.findingsMedium, report.counts.medium);
    assert.equal(wallPayload.findingsLower, report.counts.lower);
    assert.equal(typeof wallPayload.scannerVersion, "string");
  } finally {
    server.close();
  }
});

test("--no-telemetry makes zero network calls", async () => {
  const server = await startProofServer();
  try {
    const res = runCli("non-critical", [
      "--base-url",
      server.baseUrl,
      "--no-telemetry",
    ]);
    assert.equal(res.status, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
    const report = parseReport(res);
    // Findings are still printed locally; nothing is uploaded.
    assert.ok(report.findings.length > 0);
    assert.equal(report.scanHandoff.status, "skipped");
    assert.equal(report.wall.status, "skipped");
    assert.equal(report.unlockUrl, `${server.baseUrl}/fix-kit`);

    const proofCount = (await server.json("/_count")) as { count: number };
    assert.equal(proofCount.count, 0, "scan handoff must not be uploaded");
    const wallCount = (await server.json("/_wall_count")) as { count: number };
    assert.equal(wallCount.count, 0, "Wall ping must not be sent");
  } finally {
    server.close();
  }
});

test("--no-wall is an alias for --no-telemetry", async () => {
  const server = await startProofServer();
  try {
    const res = runCli("non-critical", [
      "--base-url",
      server.baseUrl,
      "--no-wall",
    ]);
    assert.equal(res.status, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
    const report = parseReport(res);
    assert.equal(report.scanHandoff.status, "skipped");
    assert.equal(report.wall.status, "skipped");
    const proofCount = (await server.json("/_count")) as { count: number };
    assert.equal(proofCount.count, 0);
  } finally {
    server.close();
  }
});

test("first-run telemetry disclosure prints once per machine", () => {
  const configHome = fs.mkdtempSync(path.join(os.tmpdir(), "ssz-firstrun-"));

  // First run: telemetry attempted, disclosure printed to stderr.
  const first = runHumanCli("non-critical", [], {
    SHIPPINGSZN_CONFIG_HOME: configHome,
  });
  assert.equal(first.status, 0, `stdout: ${first.stdout}`);
  assert.match(first.stderr, /anonymous telemetry requests/);
  assert.match(first.stderr, /scan handoff/);
  assert.match(first.stderr, /score:/);
  assert.match(first.stderr, /severity counts:/);
  assert.match(first.stderr, /files scanned:/);
  assert.match(first.stderr, /scanner version:/);
  assert.match(first.stderr, /stack tags:/);
  assert.match(first.stderr, /--no-telemetry/);
  assert.ok(
    fs.existsSync(path.join(configHome, "shippingszn", "seen")),
    "expected the first run to write the seen marker",
  );

  // Second run on the same machine: marker exists, disclosure suppressed.
  const second = runHumanCli("non-critical", [], {
    SHIPPINGSZN_CONFIG_HOME: configHome,
  });
  assert.equal(second.status, 0, `stdout: ${second.stdout}`);
  assert.doesNotMatch(second.stderr, /anonymous telemetry requests/);
});

test("CLI scan handoff posts canonical payload and returns Fix Kit URLs", async () => {
  const server = await startProofServer();
  try {
    const res = runCli("non-critical", [
      "--base-url",
      server.baseUrl,
      "--proof",
    ]);
    assert.equal(res.status, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
    const report = parseReport(res);
    assert.equal(report.scanHandoff.status, "uploaded");
    assert.equal(
      report.scanHandoff.resultId,
      "00000000-0000-4000-8000-000000000123",
    );
    assert.equal(
      report.unlockUrl,
      `${server.baseUrl}/fix-kit?scanResultId=00000000-0000-4000-8000-000000000123`,
    );
    assert.equal(
      report.scanHandoff.unlockUrl,
      `${server.baseUrl}/fix-kit?scanResultId=00000000-0000-4000-8000-000000000123`,
    );
    assert.equal(report.wall.url, `${server.baseUrl}/wall`);
    assert.ok(
      (report as unknown as { badgeMarkdown?: unknown }).badgeMarkdown ===
        undefined,
    );
    assert.ok(
      (report as unknown as { reportUrl?: unknown }).reportUrl === undefined,
    );

    const payload = (await server.json("/_last")) as {
      version: number;
      source: string;
      scanner: string;
      targetName: string;
      counts: Record<string, number>;
      findings: Array<{
        itemId?: string;
        severity: string;
        title: string;
        body: string;
        whatFailed?: string;
        whyItBlocksLaunch?: string;
        fixInstructions?: string;
        fixPrompt?: string;
        verify?: string;
        aiBuilderPrompt?: string;
        verificationStep?: string;
        location?: string;
      }>;
      filesScanned: number;
      score: number;
      label: string;
      decision: string;
      checkedAt: string;
      topNextStep: string;
      scannerVersion: string;
    };
    assert.equal(payload.version, 1);
    assert.equal(payload.source, "cli");
    assert.equal(payload.scanner, "shippingszn");
    assert.equal(payload.targetName, "Anonymous CLI scan");
    assert.equal(payload.score, report.score);
    assert.equal(typeof payload.label, "string");
    assert.deepEqual(payload.counts, report.counts);
    assert.equal(payload.filesScanned, report.filesScanned);
    assert.equal(typeof payload.topNextStep, "string");
    assert.equal(typeof payload.decision, "string");
    assert.equal(typeof payload.checkedAt, "string");
    assert.equal(typeof payload.scannerVersion, "string");
    assert.ok(payload.findings.length > 0);
    assert.equal(typeof payload.findings[0]!.itemId, "string");
    assert.equal(typeof payload.findings[0]!.severity, "string");
    assert.equal(typeof payload.findings[0]!.title, "string");
    assert.equal(typeof payload.findings[0]!.body, "string");
    // Open-core boundary: the CLI uploads diagnosis only. None of the paid
    // Fix Kit remediation fields may leave the machine.
    assert.equal(payload.findings[0]!.whatFailed, undefined);
    assert.equal(payload.findings[0]!.whyItBlocksLaunch, undefined);
    assert.equal(payload.findings[0]!.fixInstructions, undefined);
    assert.equal(payload.findings[0]!.fixPrompt, undefined);
    assert.equal(payload.findings[0]!.verify, undefined);
    assert.equal(payload.findings[0]!.aiBuilderPrompt, undefined);
    assert.equal(payload.findings[0]!.verificationStep, undefined);

    const wallCount = (await server.json("/_wall_count")) as { count: number };
    assert.equal(wallCount.count, 1);
    const wallPayload = (await server.json("/_wall_last")) as {
      source: string;
      scanResultId: string;
      score: number;
      label: string;
      filesScanned: number;
      findingsCritical: number;
      findingsHigh: number;
      findingsMedium: number;
      findingsLower: number;
      scannerVersion: string;
    };
    assert.equal(wallPayload.source, "cli");
    assert.equal(
      wallPayload.scanResultId,
      "00000000-0000-4000-8000-000000000123",
    );
    assert.equal(wallPayload.score, report.score);
    assert.equal(typeof wallPayload.label, "string");
    assert.equal(wallPayload.filesScanned, report.filesScanned);
    assert.equal(wallPayload.findingsCritical, report.counts.critical);
    assert.equal(wallPayload.findingsHigh, report.counts.high);
    assert.equal(wallPayload.findingsMedium, report.counts.medium);
    assert.equal(wallPayload.findingsLower, report.counts.lower);
    assert.equal(typeof wallPayload.scannerVersion, "string");
  } finally {
    server.close();
  }
});

test("CLI scan handoff failure returns failed status and non-zero exit", async () => {
  const server = await startProofServer();
  try {
    const res = runCli("critical", [
      "--base-url",
      `${server.baseUrl}/missing`,
      "--proof",
    ]);
    assert.equal(res.status, 1, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
    const report = parseReport(res);
    assert.ok(report.counts.critical > 0);
    assert.equal(report.scanHandoff.status, "failed");
    assert.match(report.scanHandoff.error ?? "", /HTTP 404/);
    assert.equal(report.scanHandoff.unlockUrl, undefined);
  } finally {
    server.close();
  }
});
