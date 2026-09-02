# shippingszn

Free, read-only launch inspection for AI-built apps. It finds common launch
blockers and gives you the evidence, fix instructions, AI-builder prompt, and
verification step for every finding.

```bash
npx shippingszn@latest
```

Normal scans include the complete result in the terminal and in `--json`; no
finding is hidden behind payment.

## Launch scan

```text
shippingszn [path] [options]

  --json                Machine-readable score, findings, and report status.
  --no-telemetry        Fully offline: no private report upload or Wall ping.
  --no-wall             Alias for --no-telemetry.
  --proof               Backward-compatible alias; uploads are on by default.
  --base-url <url>      Base URL for report and checklist links.
  --cwd <path>          Directory to scan. Default: current directory.
  --no-color            Disable terminal colors.
  -h, --help            Show help.
  -v, --version         Print version.
```

Each finding includes its severity, title, sanitized file location and evidence,
why it blocks launch, concrete fix instructions, a prompt for your AI builder,
and a verification step. The launch workbook and private report are free too.

## Local AI visibility with BYOK

Visibility checks call providers directly from your machine with your own API
keys. ShippingSZN never receives or stores those keys.

```bash
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
npx shippingszn@latest visibility https://example.com

# Non-interactive execution requires explicit confirmation:
npx shippingszn@latest visibility https://example.com \
  --engines openai,anthropic --yes --output ./shippingszn-visibility
```

The preflight lists selected and missing providers, prompt count, maximum call
count, and warns that your provider account may be charged. Compiled limits are
five prompts per provider, fifteen answer calls total, concurrency of two, one
retry for transient failures, and a 45-second request timeout.

Keys are accepted only through `OPENAI_API_KEY` and `ANTHROPIC_API_KEY`.
Credential command-line flags are rejected because process listings and shell
history can expose them. Reports stay local by default and are written as JSON
and Markdown into a new or empty output directory. Missing providers produce
explicit partial coverage; ShippingSZN never substitutes its own account.

## Privacy and telemetry

By default a launch scan makes two sanitized requests:

1. A private scan handoff creates a high-entropy report URL. It includes a
   pseudonymous project fingerprint, score, safe finding metadata, and sanitized
   locations/evidence. It excludes the repository URL, project name, absolute
   path, matched source lines, file contents, and secrets.
2. An anonymous Wall ping includes aggregate score, band, finding counts, file
   count, scanner version, timestamp, and safe stack tags.

The first run explains both requests. Use `--no-telemetry` for zero network
calls. Local visibility responses are not included in either request.

## Coverage

Checks include hardcoded credentials, environment-file exposure, crawl assets,
browser defenses, unsafe code patterns, auth/OTP readiness, rate limits,
paid-API spend guards, uploads, payment webhook validation, dependency
integrity, monitoring, legal pages, placeholder content, and unfinished-work
markers.

The scanner respects `.gitignore`. Inline `shippingszn:ignore` and
`shippingszn:ignore-next-line` markers suppress eligible code-pattern findings;
hardcoded-secret findings cannot be suppressed.

A clean result is not a launch certificate. Runtime behavior, provider
dashboards, and authenticated journeys still require end-user verification.

## Exit codes

- `0`: no Critical findings, or a completed visibility scan.
- `1`: one or more Critical launch findings.
- `2`: invalid input, unconfirmed visibility spend, or scanner error.

License: MIT
