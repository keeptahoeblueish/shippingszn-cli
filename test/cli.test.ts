import { strict as assert } from "node:assert";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_ROOT = path.resolve(__dirname, "..");
const TSX_BIN = path.join(CLI_ROOT, "node_modules", ".bin", "tsx");
const ENTRY = path.join(CLI_ROOT, "src", "index.ts");
const FIXTURES = path.join(__dirname, "fixtures", "cli-exit");

function runCli(fixture: string) {
  const res = spawnSync(
    TSX_BIN,
    [ENTRY, path.join(FIXTURES, fixture), "--json", "--no-color"],
    { encoding: "utf8" },
  );
  return res;
}

test("CLI exits non-zero when a critical finding is present", () => {
  const res = runCli("critical");
  assert.equal(res.status, 1, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
  const report = JSON.parse(res.stdout);
  assert.ok(report.totals.critical > 0, "expected at least one critical finding");
  assert.ok(
    report.findings.some((f: { severity: string }) => f.severity === "critical"),
  );
});

test("CLI exits 0 when no critical findings are present", () => {
  const res = runCli("clean");
  assert.equal(res.status, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
  const report = JSON.parse(res.stdout);
  assert.equal(report.totals.critical, 0);
});

test("CLI exits 0 when only non-critical findings are present", () => {
  const res = runCli("non-critical");
  assert.equal(res.status, 0, `stderr: ${res.stderr}\nstdout: ${res.stdout}`);
  const report = JSON.parse(res.stdout);
  assert.equal(report.totals.critical, 0, "expected zero critical findings");
  const nonCritical = report.totals.high + report.totals.medium + report.totals.lower;
  assert.ok(
    nonCritical > 0,
    `expected at least one non-critical finding to make this test meaningful, got totals ${JSON.stringify(report.totals)}`,
  );
});
