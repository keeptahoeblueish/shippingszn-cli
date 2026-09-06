import type { VisibilityAnswer, VisibilityEngine } from "../types.js";

export type ProviderFetch = typeof fetch;

export function citationsFromText(
  text: string,
): VisibilityAnswer["citations"] {
  const urls = text.match(/https?:\/\/[^\s)\]"'<>]+/g) ?? [];
  return [...new Set(urls.map((url) => url.replace(/[.,);:!?]+$/g, "")))]
    .slice(0, 8)
    .map((url) => ({ url }));
}

export class ProviderHttpError extends Error {
  constructor(
    readonly engine: VisibilityEngine,
    readonly status: number,
  ) {
    super(`${engine} request failed (HTTP ${status}).`);
  }
}
