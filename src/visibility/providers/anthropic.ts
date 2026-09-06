import { providerKey } from "../config.js";
import { safeProviderError } from "../redaction.js";
import type { VisibilityProvider } from "../types.js";
import {
  citationsFromText,
  ProviderHttpError,
  type ProviderFetch,
} from "./shared.js";

export function createAnthropicProvider(
  env: NodeJS.ProcessEnv = process.env,
  fetchImpl: ProviderFetch = fetch,
): VisibilityProvider {
  return {
    engine: "anthropic",
    async call(prompt, signal) {
      const key = providerKey("anthropic", env);
      if (!key) throw safeProviderError("anthropic");
      const baseUrl =
        env.ANTHROPIC_BASE_URL?.trim() || "https://api.anthropic.com/v1";
      const res = await fetchImpl(`${baseUrl.replace(/\/+$/, "")}/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": key,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: env.ANTHROPIC_MODEL?.trim() || "claude-sonnet-4-6",
          max_tokens: 700,
          system:
            "Answer as a neutral product-research assistant. Name concrete products and include source URLs when known.",
          messages: [{ role: "user", content: prompt }],
        }),
        signal,
      });
      if (!res.ok) throw new ProviderHttpError("anthropic", res.status);
      const data = (await res.json()) as {
        content?: Array<{ type?: string; text?: string }>;
      };
      const text =
        data.content
          ?.filter((item) => item.type === "text")
          .map((item) => item.text ?? "")
          .join("\n") ?? "";
      return {
        engine: "anthropic",
        prompt,
        text,
        citations: citationsFromText(text),
      };
    },
  };
}
