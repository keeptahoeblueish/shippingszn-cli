#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const nodeMajor = Number.parseInt(process.versions.node.split(".")[0], 10);
const tests = readdirSync(join(ROOT, "test"))
  .filter((name) => name.endsWith(".test.ts"))
  .sort()
  .map((name) => join("test", name));

if (tests.length === 0) throw new Error("no public CLI tests were found");

const coverageArgs = ["--experimental-test-coverage"];
if (nodeMajor >= 22) {
  coverageArgs.push(
    "--test-coverage-include=src/**",
    "--test-coverage-exclude=src/vendor/**",
    "--test-coverage-lines=90",
  );
}

const result = spawnSync(
  process.execPath,
  ["--import", "tsx", ...coverageArgs, "--test", ...tests],
  {
    cwd: ROOT,
    stdio: "inherit",
  },
);
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
