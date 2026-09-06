const SECRET_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi,
  /\bsk-[A-Za-z0-9_-]{8,}/g,
  /\b(?:ant|sk-ant)-[A-Za-z0-9_-]{8,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

export function redactSecrets(value: string): string {
  let redacted = value;
  for (const pattern of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, "[REDACTED_SECRET]");
  }
  return redacted;
}

export function safeProviderError(engine: string, status?: number): Error {
  const suffix = status ? ` (HTTP ${status})` : "";
  return new Error(`${engine} request failed${suffix}. Check the provider configuration and quota.`);
}
