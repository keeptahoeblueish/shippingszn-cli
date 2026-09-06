import { providerKey } from "../config.js";
import { safeProviderError } from "../redaction.js";
import type { VisibilityProvider } from "../types.js";
import {
  citationsFromText,
  ProviderHttpError,
  type ProviderFetch,
} from "./shared.js";

export function createOpenAIProvider(
  env: NodeJS.ProcessEnv = process.env,
  fetchImpl: ProviderFetch = fetch,
): VisibilityProvider {
  return {
    engine: "openai",
    async call(prompt, signal) {
      const key = providerKey("openai", env);
      if (!key) throw safeProviderError("openai");
      const baseUrl = env.OPENAI_BASE_URL?.trim() || "https://api.openai.com/v1";
      const res = await fetchImpl(`${baseUrl.replace(/\/+$/, "")}/responses`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${key}`,
        },
        body: JSON.stringify({
          model: env.OPENAI_MODEL?.trim() || "gpt-4.1-mini",
          instructions:
            "Answer as a neutral product-research assistant. Name concrete products and include source URLs when known.",
          input: prompt,
          max_output_tokens: 700,
          store: false,
        }),
        signal,
      });
      if (!res.ok) throw new ProviderHttpError("openai", res.status);
      const data = (await res.json()) as {
        output_text?: string;
        output?: Array<{ content?: Array<{ type?: string; text?: string }> }>;
      };
      const text =
        data.output_text ??
        data.output
          ?.flatMap((item) => item.content ?? [])
          .filter((item) => item.type === "output_text")
          .map((item) => item.text ?? "")
          .join("\n") ??
        "";
      return { engine: "openai", prompt, text, citations: citationsFromText(text) };
    },
  };
}
