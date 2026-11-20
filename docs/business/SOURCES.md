# Business documentation sources

Reviewed on 2026-09-06. This public document uses only files in the generated
repository. It contains no private records, local agent memory, credentials,
or account details.

| Source path | Date/status | Knowledge retained | Canonical destination | Conflict/disposition |
|---|---|---|---|---|
| [Package README](../../README.md) | Current source contract, reviewed 2026-09-06 | Free findings, audience, BYOK, privacy and limits | README.md, Purpose through Constraints | Source description; registry and website behavior need separate verification. |
| [CLI source](../../src/index.ts) | Current generated implementation | Complete findings, default report/Wall requests, offline option | README.md, Workflows / Constraints | No paid finding requirement; source is not a release receipt. |
| [Visibility command](../../src/visibility/command.ts) | Current generated implementation | Provider selection, spend confirmation, credential-flag rejection, local reports | README.md, Products / Workflows / Constraints | Provider charges require confirmation; missing providers are disclosed. |
| [Export manifest](../../export-manifest.json) | Generated for this source commit | Version, source commit, cleanliness, file hashes | README.md, Systems / Open questions | Identifies the export, not the npm latest tag. |
| [Package metadata](../../package.json) | Generated package contract | Distribution identity and npm file allowlist | README.md, Purpose / Systems | No publication claimed; full source docs stay in this repository. |
| [Export verifier](../../scripts/verify-export.mjs) | Generated verification contract | Manifest completeness, privacy boundaries, installed artifact, clean provenance | README.md, Source map / Open questions | Verification does not publish npm or deploy the site. |
| [License](../../LICENSE) | Existing public license | Source licensing | README.md, Source map | Export repair and documentation do not change licensing. |

## Checked locations and gaps

- Reviewed the README, package contract, manifest/verifier, launch command,
  and visibility command represented by this export.
- No private records, machine-local memory, customer data, or credentials
  are included.
- Live npm distribution and website journeys need separate release proof;
  repository observations are not commercial or deployment verification.
- The supported exporter and hash manifest include these business files.
  Generating them does not publish npm.
