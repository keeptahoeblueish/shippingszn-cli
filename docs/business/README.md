# ShippingSZN CLI business documentation

Source contract reviewed on 2026-09-06. This document describes the generated
source; it does not establish what a registry or website currently serves.
No private business records or machine-local agent memory are included.

## Purpose and scope

ShippingSZN is a free, read-only launch inspector for developers and founders
shipping AI-built applications. This repository contains standalone source for
the `shippingszn` npm package. It is a supporting component, not a separate
business.

## Customers and users

Developers, founders, and AI-builder users inspecting applications before
launch in a terminal or continuous-integration workflow.

## Products, services and business model

The source provides complete findings, evidence, fix instructions, AI-builder
prompts, and verification steps without a payment requirement. Optional local
visibility uses the user's own OpenAI or Anthropic credentials; calls may incur
provider charges and require explicit spend confirmation. This repository does
not establish commercial agreements, revenue, or current website offers. The
manifest's version identifies this export, not the registry's `latest` version.

## Core business workflows

1. Inspect a local working tree without modifying its files.
2. Review the score, severity counts, launch band, and complete findings.
3. Apply remediation and rescan.
4. Use the sanitized private report for further review. Normal scans also send
   an aggregate Wall request; `--no-telemetry` disables both requests for an
   offline launch scan.

For visibility, choose providers, review the preflight, confirm spend, and keep
JSON and Markdown reports locally. Missing providers mean explicit partial
coverage; ShippingSZN does not substitute its own provider account.

## Adopted decisions and constraints

Free findings do not make private reports public. Launch-scan uploads exclude
source-file contents, raw matched lines, absolute project paths, and unredacted
secrets. They may include sanitized relative locations and derived evidence;
Wall summaries carry aggregate data. Default launch scans are not offline.

Provider keys are accepted through environment variables, never credential
command-line flags. Visibility responses stay local and are not included in
launch telemetry. The inspector does not auto-fix a project, verify real
authentication journeys, or inspect provider dashboards. A clean scan is not
a launch certificate, security certification, or compliance attestation.

## Systems of record

| Record | Authoritative home |
|---|---|
| Public component context | This document and the linked source contract |
| Exported source provenance | [Export manifest](../../export-manifest.json) |
| Inspected project content | User's own working tree |
| Local visibility credentials and reports | User's machine |
| Private handoff and aggregate Wall records | ShippingSZN service under its documented privacy contract |
| Published package version | npm registry, independently verified for a release |

## Terminology

**Finding:** issue with severity, evidence, and remediation. **Launch band:**
summary readiness category. **Scan handoff:** sanitized results sent to the
private-report service. **Wall summary:** aggregate scan information. **BYOK:**
bring your own provider key. **Offline launch scan:** `--no-telemetry`; this
does not turn provider-based visibility into an offline service.

## Source map and conflicts

[SOURCES.md](SOURCES.md) lists only files in this generated repository. Its
README and implementation describe free full findings and local visibility.
Older published versions may differ. A source export does not prove npm
publication, website deployment, or parity across distributed components.

## Open questions

Current npm distribution and end-to-end website/package parity need release
verification. No new publication is claimed here. Every source file, including
these business documents, is included in the generated hash manifest. Private
records and agent memories are outside this public repository.
