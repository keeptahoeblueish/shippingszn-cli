# shippingszn

`shippingszn` is a local, read-only launch-readiness scanner for apps built with
AI. It runs inside the project you are about to ship and reads your files to
catch the launch debt AI builders commonly miss — leaked API keys, missing crawl
assets, weak browser defenses, dangerous code patterns, unguarded routes, and
last-mile polish gaps — then prints a 0-100 readiness score, a launch verdict,
and every finding with the file and line it came from. It never writes to your
project and needs no account to run.

## Install / usage

```bash
npx shippingszn@latest          # scan the current directory
npx shippingszn@latest ./path   # scan a specific directory
npx shippingszn@latest --no-telemetry   # run fully offline, zero network calls
# or
pnpm dlx shippingszn@latest
```

This is the open-source scanner. The optional paid **Launch Fix Kit** — the
remediation layer with per-finding fixes, prompts to paste straight into your AI
builder, the 58-item launch workbook, unlimited re-scans, and launch monitoring
— lives at <https://shippingszn.com/fix-kit>. The scanner is free and always
will be; the Fix Kit is how you fix what it finds.

The CLI **never writes, modifies, or deletes** any files - it only reads. (The
one exception is a tiny first-run marker under your config dir,
`~/.config/shippingszn/seen`, used to show the telemetry notice once.) By
default each run makes two anonymous requests: a scan handoff for checkout that
carries finding-level detail (severity, checklist item, `file:line`, and a short
evidence snippet — secret values always redacted before upload), and an
aggregate Wall summary with score, severity counts, files scanned, scanner
version, and safe stack tags. Neither uploads full source files, repo URLs,
project names, unredacted secrets, handles, or emails. Pass `--no-telemetry` to
run fully offline (zero network calls). Details in [Telemetry](#telemetry).

**The free scan is the full diagnosis.** Human output prints a verdict, a
higher-is-better Readiness Score, severity counts, and **every finding grouped
by severity** — its severity, the checklist item it maps to, the `file:line`,
and what's wrong — plus completed-checks coverage and the Fix Kit CTA. Run with
`--json` to get the same in a machine-readable shape, including the full
`findings` array:

```json
{
  "score": 60,
  "band": "fix_first",
  "counts": { "critical": 0, "high": 11, "medium": 1, "lower": 1 },
  "filesScanned": 128,
  "coverage": { "checksCompleted": 19, "checklistAreas": 51 },
  "scannerVersion": "0.10.0",
  "findings": [
    {
      "checkId": "hardcoded-secrets",
      "itemId": "secrets",
      "severity": "high",
      "itemTitle": "Lock up your API keys and passwords",
      "file": "src/lib/config.ts",
      "line": 12,
      "message": "Possible hardcoded API key detected.",
      "permalink": "https://shippingszn.com/i/secrets"
    }
  ],
  "unlockUrl": "https://shippingszn.com/fix-kit?scanResultId=00000000-0000-4000-8000-000000000123",
  "scanHandoff": {
    "status": "uploaded",
    "resultId": "00000000-0000-4000-8000-000000000123",
    "unlockUrl": "https://shippingszn.com/fix-kit?scanResultId=00000000-0000-4000-8000-000000000123"
  }
}
```

The findings are free. What's **paid** is the remediation layer: per-finding fix
instructions, prompts to paste straight into your AI builder, the 58-item launch
workbook, unlimited re-scans, and launch monitoring. The free CLI tells you
exactly what's wrong; the Launch Fix Kit is how you fix it.

## Telemetry

Plain `npx shippingszn@latest` makes **two** anonymous requests per run:

1. **Scan handoff** (`POST /api/scan-results`) — powers the `/fix-kit` link the
   CLI prints. It carries finding-level detail: each finding's severity, the
   checklist item it maps to, its `file:line` location, and a short evidence
   snippet from the matched line. Secret values are always redacted to a
   `abc123…x9z2` form before upload. It does not include your repo URL, project
   name, or full source files.
2. **Aggregate Wall summary** (`POST /api/wall`) — intentionally small: score,
   launch label, files scanned, finding counts by severity, detected stack
   tags, scanner version, and timestamp. No paths, no filenames, no
   finding-level detail.

On the **first run on a machine**, the CLI prints a description of both requests
plus the exact aggregate payload (to stderr, so it never corrupts `--json`
output) and a note that you can turn it off. Telemetry is default-on but fully
transparent and opt-out-able:

```bash
npx shippingszn@latest --no-telemetry   # zero network calls, fully offline
```

`--no-wall` is an alias for `--no-telemetry`. With telemetry off, the CLI makes
**no** scan-handoff upload and **no** Wall ping.

The same run also creates a scan-specific paid-report handoff. The terminal
prints a `/fix-kit?scanResultId=...` URL so checkout can carry that scan into
the Launch Fix Kit after purchase. `--proof` is still accepted for old docs, but
it is no longer required.

## What gets checked

The initial check set is intentionally small and high-signal. Each finding
maps back to one of the items on the checklist.

- Hardcoded API keys across many providers (OpenAI, Anthropic, Stripe, AWS,
  Google, GitHub, Slack, private key blocks).
- `.env` present but not ignored in `.gitignore`, or `.env` present but no
  `.env.example`.
- Missing `.gitignore`, `robots.txt`, `sitemap.xml`, or a custom favicon.
- Missing security-header middleware in common server configs.
- Dangerous code patterns: unsafe HTML injection in React, runtime
  code-execution calls, wildcard CORS.
- OTP/auth readiness signals: phone normalization, resend/cooldown behavior,
  anti-enumeration copy, mobile one-time-code input, delivery-smoke evidence,
  recovery paths, and paid report access that depends on OTP.
- Python: common debug-mode slip-ups, hardcoded framework secrets, missing
  env-var loading.
- Ruby: unsafe string rendering, hardcoded Rails secrets.
- Go: `http.ListenAndServe` without TLS, hardcoded token / apiKey / secret
  literals.
- Placeholder content (`lorem ipsum`, `John Doe`, `test@example.com`) and
  `TODO` / `FIXME` / `XXX` / `HACK` comments.

Each finding is tagged Critical, High, Medium, or Lower and maps to the relevant
checklist item. All of that finding-level detail is free and printed on every
run; the Fix Kit turns it into the human launch decision and AI-builder punch
list of fixes.

## Scoring

The 0-100 Readiness Score is not a black box. Each finding subtracts a fixed
number of penalty points from 100 based on its severity:

| Severity | Penalty per finding |
| -------- | ------------------- |
| Critical | 35                  |
| High     | 22                  |
| Medium   | 10                  |
| Lower    | 5                   |

The raw score is `100 - (sum of all penalties)`, clamped to the `0-100` range.
The score is then floored into a severity band so the number can never contradict
the verdict — the most severe finding present sets the band ceiling:

| Band                 | Score range | Trigger                                   |
| -------------------- | ----------- | ----------------------------------------- |
| Fix now (no-go)      | 0-59        | any Critical finding caps the score at 59 |
| Fix-first            | 60-79       | any High finding (no Critical) caps at 79 |
| Verify before launch | 80-89       | any Medium finding (no Critical/High)     |
| Launchable           | 90-100      | only Lower findings, or a clean scan      |

So one Critical finding alone drops you to at most 59 ("Fix now") regardless of
how few findings there are; a single High caps you at 79 ("Fix-first"). Count
pressure moves the score inside its band. The CLI runs with no source-side score
cap — the score you see is the severity-banded score.

## Suppressing false positives

Two opt-out mechanisms, both off by default:

- **`.gitignore` is respected.** Files your repo gitignores (build output,
  generated reports, local `.env`, vendored sub-projects) are skipped.
  This works automatically inside any git repo; outside a git repo the
  scanner falls back to walking the full directory.
- **Inline ignore markers.** For one-off cases where a file legitimately
  contains a pattern the scanner detects (a regex literal, copy that
  describes a placeholder, a test fixture), add one of:

  ```ts
  // shippingszn:ignore — placed on the same line as the match
  const x = "lorem ipsum"; // shippingszn:ignore — fixture text

  // shippingszn:ignore-next-line — placed on the line above the match
  // shippingszn:ignore-next-line
  const greeting = "hello placeholder";
  ```

  Markers apply to substring/regex checks (placeholder content, dangerous
  patterns, language patterns). They deliberately do **not** apply to
  hardcoded-secret detection — false positives there should be addressed
  by removing the secret pattern, not by allowlisting.

## What does NOT get checked

These are deliberately out of scope for v1:

- Anything that requires running your app (no live HTTP probing, no auth
  flows).
- Auto-fixing problems. The CLI is read-only.
- Deep static analysis or language-specific lints. Use ESLint, Semgrep, or
  Snyk for that.
- Validating your actual third-party dashboards (Stripe spend caps, OpenAI
  quotas, etc.).

A clean report is **not** a launch certificate — it just means none of the
obvious things tripped a tripwire. Use the Fix Kit, owner-verification items, and
rerun loop before you ship.

## Usage

```text
shippingszn [path] [options]

Options:
  --json                Output a machine-readable JSON summary (includes the
                        full findings array).
  --no-telemetry        Run fully offline: no scan handoff, no Wall ping, zero
                        network calls. (--no-wall is an alias.)
  --proof               Backward-compatible alias. Normal runs already return
                        a scan-specific Launch Fix Kit URL.
  --base-url <url>      Base URL used to build checkout and Fix Kit links.
  --cwd <path>          Directory to scan. Default: current working directory.
  --no-color            Disable ANSI colors in the human-readable summary.
  -h, --help            Show help.
  -v, --version         Print version.
```

## Exit codes

- `0` — No critical findings.
- `1` — One or more critical findings detected.
- `2` — The scanner itself crashed.

This makes the CLI suitable for CI:

```yaml
# .github/workflows/launch-check.yml
- run: npx shippingszn@latest --json > launch-check.json
```

For PR scan signal, have GitHub Actions run the scanner and post the JSON
summary as a comment: score, severity counts, findings, and unlock URL.

## Privacy

`shippingszn` reads files on your machine. It never uploads source code. By
default it creates a scan handoff for checkout and makes one best-effort
outbound request to post anonymous Wall stats: score, launch label, files
scanned count, finding counts by severity, detected stack tags, scanner version,
and timestamp. Wall stats never include source code, file paths, filenames,
project names, repo URLs, secrets, emails, handles, finding titles, evidence, or
report contents. The first run on a machine prints the exact payload to stderr,
and `--no-telemetry` (alias `--no-wall`) turns off all network calls.

## License

MIT. See [LICENSE](./LICENSE).
