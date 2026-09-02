import { strict as assert } from "node:assert";
import { test } from "node:test";
import { permalinkFor, CHECKLIST_ITEMS } from "../src/items.js";

test("permalinkFor builds canonical /i/<id> URLs and trims trailing slashes", () => {
  assert.equal(
    permalinkFor("secrets", "https://example.com"),
    "https://example.com/i/secrets",
  );
  assert.equal(
    permalinkFor("secrets", "https://example.com/"),
    "https://example.com/i/secrets",
  );
  assert.equal(
    permalinkFor("secrets", "https://example.com///"),
    "https://example.com/i/secrets",
  );
});

test("every referenced item id has a registered checklist entry", () => {
  for (const id of [
    "secrets",
    "common-attacks",
    "https-headers",
    "dev-prod-data",
    "github",
    "seo",
    "launch-polish",
    "ai-audit",
  ]) {
    assert.ok(CHECKLIST_ITEMS[id], `missing checklist entry for ${id}`);
    assert.equal(CHECKLIST_ITEMS[id].id, id);
  }
});
