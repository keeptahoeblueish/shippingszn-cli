# AGENTS.md

## Source control authority (2026-08-24)

GitHub `keeptahoeblueish/shippingszn-cli` is authoritative. Cursor cloud agents
use the bidirectional code mirror `novus/keeptahoeblueish-shippingszn-cli`.
GitHub is the operational pull-request record while Cursor's documented PR
synchronization is live-failing. The native Origin repository
`novus/shippingszn-cli` is transitional continuity for in-flight work and
existing provider links; it is not the mirror, but newer work there must never
be ignored. Mac checkouts fetch from GitHub and retain both Origin surfaces
explicitly. Do not detach the mirror, delete the transitional repository,
change npm publication, or release a package without the required verification
and Ryan's explicit approval.

This is a read-only launch inspector distributed publicly as the `shippingszn` npm package. Read `README.md` for its privacy and product contract. Run `npm run verify:release` before any approved release. Never print or upload source code, matched source lines, absolute paths, or unredacted secret values.
