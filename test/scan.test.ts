import { strict as assert } from "node:assert";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  listFiles,
  readFileSafe,
  ScanInputError,
  ScanLimitError,
} from "../src/scan";

async function tempDir(t: { after(fn: () => Promise<void>): void }) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "shippingszn-scan-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}

test("listFiles rejects missing targets and regular files", async (t) => {
  const dir = await tempDir(t);
  const file = path.join(dir, "file.ts");
  await fs.writeFile(file, "export {};\n");

  await assert.rejects(
    () => listFiles(path.join(dir, "missing")),
    ScanInputError,
  );
  await assert.rejects(() => listFiles(file), ScanInputError);
});

test("listFiles fails explicitly instead of silently truncating file coverage", async (t) => {
  const dir = await tempDir(t);
  await Promise.all(
    ["a.ts", "b.ts", "c.ts"].map((name) =>
      fs.writeFile(path.join(dir, name), "export {};\n"),
    ),
  );

  await assert.rejects(
    () => listFiles(dir, { maxFiles: 2 }),
    (err: unknown) =>
      err instanceof ScanLimitError && /more than 2 files/.test(err.message),
  );
});

test("listFiles fails explicitly when directory depth exceeds the safety ceiling", async (t) => {
  const dir = await tempDir(t);
  const nested = path.join(dir, "one", "two");
  await fs.mkdir(nested, { recursive: true });
  await fs.writeFile(path.join(nested, "deep.ts"), "export {};\n");

  await assert.rejects(
    () => listFiles(dir, { maxDepth: 1 }),
    (err: unknown) =>
      err instanceof ScanLimitError && /depth exceeds/.test(err.message),
  );
});

test("listFiles never follows a symlink outside the target tree", async (t) => {
  const dir = await tempDir(t);
  const outside = await tempDir(t);
  await fs.writeFile(path.join(dir, "inside.ts"), "export {};\n");
  await fs.writeFile(path.join(outside, "secret.ts"), "do not scan\n");
  await fs.symlink(outside, path.join(dir, "outside-link"));

  const files = await listFiles(dir);
  assert.deepEqual(
    files.map((file) => file.relPath),
    ["inside.ts"],
  );
});

test("readFileSafe enforces the byte cap even when a file grows after listing", async (t) => {
  const dir = await tempDir(t);
  const filePath = path.join(dir, "growing.ts");
  await fs.writeFile(filePath, "small\n");
  const [listed] = await listFiles(dir);
  assert.ok(listed);

  await fs.writeFile(filePath, Buffer.alloc(512 * 1024 + 1, "a"));
  assert.equal(await readFileSafe(listed), null);
});
