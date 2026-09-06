# ShippingSZN CLI business documentation

Public-source consolidation reviewed on 2026-09-06. No private business records, machine-local memory, credentials, or account details are included.

## Purpose and scope

This repository distributes the ShippingSZN local launch inspector as the `shippingszn` npm package. It is a supporting product component, not a separate business. This documentation summarizes the public source repository, not a live npm or website check.

## Customers and users

Developers and founders preparing to launch AI-built applications, including people running the inspector in a terminal or continuous-integration workflow.

## Products, services and business model

The public README presents a local scan that summarizes launch findings and links to a Launch Fix Kit. It describes a paid, project-bound Kit and a separate recurring-monitoring product. These are statements in this checkout's product contract, not independent confirmation of current website offers or pricing. The export manifest records package version 0.11.0; it does not prove what npm currently serves as `latest`.

## Core business workflows

1. Run the local inspector against a project working tree.
2. Review its score, severity counts, and launch band.
3. Follow the described report/remediation path and rescan after fixes.

Default runs make a sanitized scan handoff and aggregate Wall request. The documented `--no-telemetry` flag disables all network calls. Inspection does not modify target-project files; a small first-run marker in the user's configuration directory records telemetry-notice display.

## Adopted decisions and constraints

The public privacy contract excludes source-file contents, raw matched lines, absolute project paths, and unredacted secret values from uploads. Handoffs may include relative file/line locations and derived/redacted evidence; aggregate Wall data is narrower. Default mode is not offline. The inspector does not auto-fix, execute a running application, test real auth flows, perform deep static analysis, or inspect provider dashboards. A clean scan is not a launch certificate.

## Systems of record

| Record | Authoritative home |
|---|---|
| Public component context | This document, grounded in public sources |
| Exported source provenance | [Export manifest](../../export-manifest.json) |
| Inspected project content | User's own working tree |
| Scan handoff and Wall records | ShippingSZN service under its documented contract |
| Published package version | npm registry; not checked for this documentation pass |

## Terminology

**Finding:** issue detected by implemented checks. **Launch band:** summary of the scan's severity profile. **Scan handoff:** sanitized results sent to the web service. **Wall summary:** aggregate report-card information. **Offline mode:** the explicit no-telemetry invocation.

## Source map and conflicts

[SOURCES.md](SOURCES.md) lists only public repository sources. Repository claims about paid access, telemetry, and version describe this checkout; a live website or package may differ and must be checked before making a current commercial claim. A generated export is not an independent product decision authority.

## Open questions

Current npm distribution, current commercial offers, and end-to-end website/package parity are not verified. This repository's source verifier requires every file to be included in its generated manifest. Business documentation is included through the existing committed export source; this documentation change preserves the existing runtime, package, and verification files.
