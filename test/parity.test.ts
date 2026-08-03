import { strict as assert } from "node:assert";
import { test } from "node:test";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { CHECKLIST_PUBLIC as CHECKLIST } from "../src/vendor/checklist-data/public.js";
import { CHECKLIST_ITEMS } from "../src/items.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_SRC = path.resolve(__dirname, "..", "src");

const ITEM_ID_KEY_PATTERN = /\bitemId:\s*"([a-z0-9-]+)"/g;
async function collectMatches(
  dir: string,
  pattern: RegExp,
  filePredicate: (name: string) => boolean,
): Promise<Set<string>> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const hits = new Set<string>();
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      for (const v of await collectMatches(full, pattern, filePredicate))
        hits.add(v);
      continue;
    }
    if (!entry.isFile() || !filePredicate(entry.name)) continue;
    const content = await fs.readFile(full, "utf8");
    const re = new RegExp(pattern.source, pattern.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) hits.add(m[1]);
  }
  return hits;
}

test("every itemId emitted by the CLI maps to a real web checklist id", async () => {
  const webIds = new Set(CHECKLIST.map((item) => item.id));

  assert.ok(
    webIds.size >= 40,
    `expected to load the shared checklist ids, got ${webIds.size}`,
  );

  const cliItemIds = await collectMatches(
    CLI_SRC,
    ITEM_ID_KEY_PATTERN,
    (name) => name.endsWith(".ts"),
  );

  assert.ok(
    cliItemIds.size > 0,
    "expected the CLI to emit at least one itemId; found none",
  );

  const orphaned = [...cliItemIds].filter((id) => !webIds.has(id)).sort();

  assert.deepEqual(
    orphaned,
    [],
    `CLI emits itemIds missing from @workspace/checklist-data. Either rename the CLI itemId to match an existing checklist item, or add the missing item to the shared checklist. Orphans: ${JSON.stringify(orphaned)}`,
  );
});

test("CHECKLIST_ITEMS registry in items.ts matches automated checklist coverage", () => {
  const registryIds = new Set(Object.keys(CHECKLIST_ITEMS));
  const automatedIds = new Set(
    CHECKLIST.filter((item) => item.cliCoverage === "automated").map(
      (item) => item.id,
    ),
  );

  assert.ok(
    registryIds.size > 0,
    "expected at least one entry in the CLI checklist registry",
  );

  const registryOnly = [...registryIds]
    .filter((id) => !automatedIds.has(id))
    .sort();
  const checklistOnly = [...automatedIds]
    .filter((id) => !registryIds.has(id))
    .sort();

  assert.deepEqual(
    registryOnly,
    [],
    `CLI registry includes items that @workspace/checklist-data does not classify as automated. Registry-only: ${JSON.stringify(registryOnly)}`,
  );
  assert.deepEqual(
    checklistOnly,
    [],
    `@workspace/checklist-data classifies items as automated that are missing from the CLI registry. Checklist-only: ${JSON.stringify(checklistOnly)}`,
  );
});

test("automated checklist items are emitted by CLI checks and manual items are not", async () => {
  const cliItemIds = await collectMatches(
    CLI_SRC,
    ITEM_ID_KEY_PATTERN,
    (name) => name.endsWith(".ts"),
  );
  const automatedIds = CHECKLIST.filter(
    (item) => item.cliCoverage === "automated",
  )
    .map((item) => item.id)
    .sort();
  const manualIds = CHECKLIST.filter(
    (item) => item.cliCoverage === "manual_only",
  )
    .map((item) => item.id)
    .sort();

  const missingAutomatedCoverage = automatedIds.filter(
    (id) => !cliItemIds.has(id),
  );
  const emittedManualItems = manualIds.filter((id) => cliItemIds.has(id));

  assert.deepEqual(
    missingAutomatedCoverage,
    [],
    `Items marked cliCoverage: automated must have at least one emitted CLI itemId. Missing: ${JSON.stringify(missingAutomatedCoverage)}`,
  );
  assert.deepEqual(
    emittedManualItems,
    [],
    `Items marked cliCoverage: manual_only must not be emitted by CLI checks. Emitted manual-only ids: ${JSON.stringify(emittedManualItems)}`,
  );
});
