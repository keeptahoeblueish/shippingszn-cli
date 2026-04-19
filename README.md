# shippingszn

A small, read-only CLI that scans a project for common pre-launch issues from
the [shippingszn.com launch checklist](https://shippingszn.com). Run it
before you ship to catch obvious mistakes — leaked API keys, missing
`robots.txt`, no security headers, and so on — and get a friendly report
linking each finding back to the matching checklist item.

```bash
npx shippingszn
# or
pnpm dlx shippingszn
```

Run it inside any project root. The CLI **never writes, modifies, or deletes**
any files — it only reads. Everything stays on your machine.

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
- Python: common debug-mode slip-ups, hardcoded framework secrets, missing
  env-var loading.
- Ruby: unsafe string rendering, hardcoded Rails secrets.
- Go: `http.ListenAndServe` without TLS, hardcoded token / apiKey / secret
  literals.
- Placeholder content (`lorem ipsum`, `John Doe`, `test@example.com`) and
  `TODO` / `FIXME` / `XXX` / `HACK` comments.

Each finding is tagged Critical, High, Medium, or Lower and links back to the
relevant checklist item on shippingszn.com.

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
obvious things tripped a tripwire. Walk through the full checklist before you
ship.

## Usage

```text
shippingszn [path] [options]

Options:
  --json                Output a machine-readable JSON report.
  --base-url <url>      Base URL used to build links back to checklist items.
  --cwd <path>          Directory to scan. Default: current working directory.
  --no-color            Disable ANSI colors in the human-readable report.
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
- run: npx shippingszn --json > launch-check.json
```

## Privacy

`shippingszn` reads files on your machine. It never uploads source code,
makes outbound network calls, or phones home. No telemetry. No accounts.
Inspect the source or audit `npm pack --dry-run` to confirm.

## License

MIT. See [LICENSE](./LICENSE).
