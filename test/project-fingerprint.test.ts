import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { projectFingerprint } from "../src/project-fingerprint.js";

const FINGERPRINT_PATTERN = /^sszpf1_[a-f0-9]{64}$/;

test("project fingerprint is stable across SSH and HTTPS clones", (t) => {
  const root = mkdtempSync(join(tmpdir(), "shippingszn-fingerprint-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  execFileSync("git", ["init", "-q", root]);
  execFileSync("git", [
    "-C",
    root,
    "remote",
    "add",
    "origin",
    "git@github.com:example/launch-app.git",
  ]);

  const sshFingerprint = projectFingerprint(root);
  execFileSync("git", [
    "-C",
    root,
    "remote",
    "set-url",
    "origin",
    "https://github.com/example/launch-app.git",
  ]);
  const httpsFingerprint = projectFingerprint(root);

  assert.match(sshFingerprint, FINGERPRINT_PATTERN);
  assert.equal(httpsFingerprint, sshFingerprint);
  assert.doesNotMatch(sshFingerprint, /github|example|launch-app/i);
});

test("local project fingerprint is stable without exposing its path", (t) => {
  const root = mkdtempSync(join(tmpdir(), "shippingszn-local-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const first = projectFingerprint(root);
  const second = projectFingerprint(root);

  assert.match(first, FINGERPRINT_PATTERN);
  assert.equal(second, first);
  assert.equal(first.includes(root), false);
});
