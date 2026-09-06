import { strict as assert } from "node:assert";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { createAnthropicProvider } from "../src/visibility/providers/anthropic.js";
import { createOpenAIProvider } from "../src/visibility/providers/openai.js";
import { ProviderHttpError } from "../src/visibility/providers/shared.js";
import { redactSecrets } from "../src/visibility/redaction.js";
import { writeVisibilityReport } from "../src/visibility/report.js";
import { runLocalVisibilityScan } from "../src/visibility/run.js";
import type { VisibilityProvider } from "../src/visibility/types.js";

const roots: string[] = [];
after(async () => Promise.all(roots.map((root) => rm(root, { recursive: true, force: true }))));

function credential(prefix: string): string {
  return `${prefix}${"fixture".repeat(6)}`;
}

function provider(engine: "openai" | "anthropic", call: VisibilityProvider["call"]): VisibilityProvider {
  return { engine, call };
}

test("requires explicit spend confirmation before provider calls", async () => {
  let calls = 0;
  await assert.rejects(
    runLocalVisibilityScan(
      { url: "https://example.com", engines: ["openai"], prompts: ["test"], confirmed: false },
      {
        env: { OPENAI_API_KEY: credential("sk-") },
        providers: { openai: provider("openai", async () => { calls++; throw new Error("unexpected"); }) },
      },
    ),
    /not confirmed/,
  );
  assert.equal(calls, 0);
});

test("enforces prompt and engine limits", async () => {
  const base = { url: "https://example.com", confirmed: true };
  await assert.rejects(
    runLocalVisibilityScan({ ...base, engines: ["openai", "openai"], prompts: ["test"] }),
    /unique/,
  );
  await assert.rejects(
    runLocalVisibilityScan({ ...base, engines: ["openai"], prompts: ["1", "2", "3", "4", "5", "6"] }),
    /At most 5 prompts/,
  );
});

test("reports partial coverage without exposing credentials", async () => {
  const key = credential("sk-");
  const report = await runLocalVisibilityScan(
    {
      url: "https://example.com",
      engines: ["openai", "anthropic"],
      prompts: ["What is Example?"],
      confirmed: true,
    },
    {
      env: { OPENAI_API_KEY: key },
      now: () => new Date("2026-08-30T00:00:00.000Z"),
      providers: {
        openai: provider("openai", async (prompt) => ({
          engine: "openai", prompt, text: "Example https://example.com/about", citations: [],
        })),
      },
    },
  );
  assert.deepEqual(report.enginesCompleted, ["openai"]);
  assert.deepEqual(report.enginesMissing, ["anthropic"]);
  assert.equal(JSON.stringify(report).includes(key), false);
});

test("caps concurrency at two calls", async () => {
  let active = 0;
  let maximum = 0;
  const fake = provider("openai", async (prompt) => {
    active++;
    maximum = Math.max(maximum, active);
    await new Promise((resolve) => setTimeout(resolve, 5));
    active--;
    return { engine: "openai", prompt, text: "done", citations: [] };
  });
  await runLocalVisibilityScan(
    { url: "https://example.com", engines: ["openai"], prompts: ["1", "2", "3", "4", "5"], confirmed: true },
    { env: { OPENAI_API_KEY: credential("sk-") }, providers: { openai: fake } },
  );
  assert.equal(maximum, 2);
});

test("retries transient failures once but never retries authentication failures", async () => {
  let transientCalls = 0;
  const transient = provider("openai", async (prompt) => {
    transientCalls++;
    if (transientCalls === 1) throw new ProviderHttpError("openai", 429);
    return { engine: "openai", prompt, text: "done", citations: [] };
  });
  await runLocalVisibilityScan(
    { url: "https://example.com", engines: ["openai"], prompts: ["test"], confirmed: true },
    { env: { OPENAI_API_KEY: credential("sk-") }, providers: { openai: transient } },
  );
  assert.equal(transientCalls, 2);

  let authCalls = 0;
  await assert.rejects(
    runLocalVisibilityScan(
      { url: "https://example.com", engines: ["openai"], prompts: ["test"], confirmed: true },
      { env: { OPENAI_API_KEY: credential("sk-") }, providers: { openai: provider("openai", async () => { authCalls++; throw new ProviderHttpError("openai", 401); }) } },
    ),
    /HTTP 401/,
  );
  assert.equal(authCalls, 1);
});

test("provider adapters send bounded requests and extract text", async () => {
  const openAIKey = credential("sk-");
  const openAIFetch = async (input: string | URL | Request, init?: RequestInit) => {
    assert.equal(String(input), "https://api.openai.com/v1/responses");
    assert.equal((init?.headers as Record<string, string>).authorization, `Bearer ${openAIKey}`);
    const body = JSON.parse(String(init?.body));
    assert.equal(body.store, false);
    assert.equal(body.max_output_tokens, 700);
    return new Response(JSON.stringify({ output_text: "OpenAI answer https://example.com" }), { status: 200 });
  };
  const openAI = createOpenAIProvider({ OPENAI_API_KEY: openAIKey }, openAIFetch as typeof fetch);
  const openAIAnswer = await openAI.call("question", new AbortController().signal);
  assert.equal(openAIAnswer.text.startsWith("OpenAI answer"), true);
  assert.deepEqual(openAIAnswer.citations, [{ url: "https://example.com" }]);

  const anthropicKey = credential("ant-");
  const anthropicFetch = async (input: string | URL | Request, init?: RequestInit) => {
    assert.equal(String(input), "https://api.anthropic.com/v1/messages");
    assert.equal((init?.headers as Record<string, string>)["x-api-key"], anthropicKey);
    const body = JSON.parse(String(init?.body));
    assert.equal(body.max_tokens, 700);
    return new Response(JSON.stringify({ content: [{ type: "text", text: "Anthropic answer" }] }), { status: 200 });
  };
  const anthropic = createAnthropicProvider({ ANTHROPIC_API_KEY: anthropicKey }, anthropicFetch as typeof fetch);
  assert.equal((await anthropic.call("question", new AbortController().signal)).text, "Anthropic answer");
});

test("redacts credentials and refuses to overwrite report directories", async () => {
  const key = credential("sk-");
  assert.equal(redactSecrets(`failed Bearer ${key}`).includes(key), false);
  const root = await mkdtemp(join(tmpdir(), "shippingszn-visibility-"));
  roots.push(root);
  const output = join(root, "report");
  const report = {
    schemaVersion: 1 as const,
    executionMode: "local_byok" as const,
    targetUrl: "https://example.com",
    enginesRequested: ["openai" as const],
    enginesCompleted: ["openai" as const],
    enginesMissing: [],
    answers: [{ engine: "openai" as const, prompt: "test", text: "answer", citations: [] }],
    generatedAt: "2026-08-30T00:00:00.000Z",
  };
  const paths = await writeVisibilityReport(report, output);
  assert.equal((await readFile(paths.jsonPath, "utf8")).includes(key), false);
  await assert.rejects(writeVisibilityReport(report, output), /not empty/);
  await writeFile(join(root, "marker"), "keep");
});
