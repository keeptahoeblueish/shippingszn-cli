# shippingszn

Primary local launch inspector for AI-built apps. Run it inside the app you are
about to ship to catch the launch debt AI builders commonly miss: leaked API
keys, missing crawl assets, weak browser defenses, dangerous code patterns, and
last-mile polish gaps.

```bash
npx shippingszn@latest
# or
pnpm dlx shippingszn@latest
```

The CLI **never writes, modifies, or deletes** any files - it only reads. (The
one exception is a tiny first-run marker under your config dir,
`~/.config/shippingszn/seen`, used to show the telemetry notice once.) By
default each run creates a scan handoff for checkout and sends one anonymous
Wall report-card summary with score, severity counts, files scanned, scanner
version, and safe stack tags. The handoff includes a stable opaque project
fingerprint so shippingszn can recognize matched paid rescans without receiving
the repo URL, project name, or absolute project path. It never uploads matched
source lines, source-file contents, unredacted secrets, handles, or emails.
Pass `--no-telemetry` to run fully offline (zero network calls).

**The free scan is the launch scoreboard.** Its result contains only a verdict,
a higher-is-better Readiness Score, severity counts, and a launch band. It does
not reveal finding titles, checklist content, file paths, evidence, fix steps,
or AI-builder prompts. The Fix Kit CTA and locked handoff metadata stay visible
so the matched project can be purchased. Run with `--json` to get the same
score-level result in a machine-readable shape:

```json
{
  "score": 60,
  "band": "fix_first",
  "counts": { "critical": 0, "high": 11, "medium": 1, "lower": 1 },
  "filesScanned": 128,
  "scannerVersion": "0.11.0",
  "detailsLocked": true,
  "unlockUrl": "https://shippingszn.com/fix-kit?scanResultId=00000000-0000-4000-8000-000000000123",
  "scanHandoff": {
    "status": "uploaded",
    "resultId": "00000000-0000-4000-8000-000000000123",
    "unlockUrl": "https://shippingszn.com/fix-kit?scanResultId=00000000-0000-4000-8000-000000000123"
  }
}
```

### Upgrading from 0.10.x

Version 0.11 intentionally removes the `findings` array from free human and
JSON output. JSON responses now set `detailsLocked` to `true` and expose only
the score, severity counts, launch band, and paid handoff metadata. The 0.10
line is superseded and unsupported; consumers of its old finding-level JSON
must migrate to the score-level 0.11 contract.

One $49 Launch Fix Kit is bound to one matched project. It includes the exact
findings, file evidence, per-finding fix instructions, AI-builder prompts, the
full 58-item launch workbook, and unlimited matched re-scans for that project.
One global Codex OAuth connection works from any local Codex project, but paid
data for an unrelated project is denied. Checkout purchases the Fix Kit but
does not sign you in; OTP sign-in is required before paid report or OAuth
access. Compatible legacy purchases that predate secure project binding can be
linked once from Account when their original repository scan and paid report
context are still available: run a fresh score-only scan in the exact project,
select the exact owned purchase, and permanently confirm that one project. If
Account says that context is missing or incompatible, use
https://shippingszn.com/support#codex-mcp for a manual access review. Recurring
launch monitoring is a separate product and is not included in the Fix Kit.

## Telemetry

Plain `npx shippingszn@latest` makes **two** telemetry requests per run. The
locked handoff is pseudonymous; the Wall ping is anonymous:

1. **Scan handoff** (`POST /api/scan-results`) — powers the `/fix-kit` link the
   CLI prints. It carries a stable pseudonymous project fingerprint used only
   to match paid rescans and enforce one-project access. It also carries each
   finding's severity, checklist item, `file:line` location, and a short derived
   or redacted evidence category. It never carries matched source lines,
   source-file contents, the repo URL, project name, absolute project path, or
   unredacted secret values.
2. **Aggregate Wall ping** (`POST /api/wall`) — intentionally small: score,
   launch label, files scanned, finding counts by severity, detected stack
   tags, scanner version, and timestamp. No paths, no filenames, no
   finding-level detail.

On the **first run on a machine**, the CLI prints a description of both requests,
including the stable project fingerprint category, plus the exact aggregate
payload (to stderr, so it never corrupts `--json` output) and a note that you
can turn it off. Telemetry is default-on but fully transparent and opt-out-able:

```bash
npx shippingszn@latest --no-telemetry   # zero network calls, fully offline
```

`--no-wall` is an alias for `--no-telemetry`. With telemetry off, the CLI makes
**no** scan-handoff upload and **no** Wall ping.

The same run also creates a scan-specific paid-report handoff. The terminal
prints a `/fix-kit?scanResultId=...` URL so checkout can carry that scan into
the project-bound Launch Fix Kit after purchase. Checkout does not sign you in;
complete OTP sign-in to open the paid Kit. `--proof` is still accepted for old
docs, but it is no longer required.

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

Internally, each finding is tagged Critical, High, Medium, or Lower and maps to
the relevant checklist item. The free output rolls those findings into the
scoreboard. The Fix Kit opens the finding-level diagnosis, human launch
decision, and AI-builder punch list.

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
  --json                Output a machine-readable score, severity counts, and
                        launch band summary.
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
summary as a comment: score, severity counts, launch band, and unlock URL.

## Privacy

`shippingszn` reads files on your machine. It never uploads source code. By
default it makes two requests. The locked checkout handoff contains a stable
pseudonymous project fingerprint plus each finding's severity, checklist item,
relative file-and-line location, and short derived or redacted evidence
category; it never contains matched source lines, source-file contents, an
absolute project path, or unredacted secrets. The anonymous Wall request
contains only score, launch label, files-scanned count, severity counts,
detected stack tags, scanner version, and timestamp. It never contains file
paths, filenames, project names, repo URLs, emails, handles, finding titles,
evidence, or report contents. The first run on a machine prints this contract
and that run's exact aggregate Wall values to stderr. `--no-telemetry` (alias
`--no-wall`) turns off both requests and every other network call.

## License

MIT. See [LICENSE](./LICENSE).
