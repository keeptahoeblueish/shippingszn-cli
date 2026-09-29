# AGENTS.md

## Source control authority (2026-08-24)

GitHub `keeptahoeblueish/shippingszn-cli` is authoritative. Cursor cloud agents use the inbound GitHub mirror `novus/keeptahoeblueish-shippingszn-cli`. The native Origin repository `novus/shippingszn-cli` is legacy continuity only; do not start authoritative work there. Mac checkouts fetch from GitHub and retain both Origin surfaces explicitly. Do not detach the mirror, delete the legacy repository, change npm publication, or release a package without the required verification and Ryan's explicit approval.

This is a read-only launch inspector distributed publicly as the `shippingszn` npm package. Read `README.md` for its privacy and product contract. Run `npm run verify:release` before any approved release. Never print or upload source code, matched source lines, absolute paths, or unredacted secret values.

## Writing rules

All prose in this repo, including docs, READMEs, PR descriptions, commit messages, comments, and reports, follows Orwell's six rules:

1. Never use a figure of speech you are used to seeing in print.
2. Never use a long word where a short one works.
3. If you can cut a word, cut it.
4. Never use the passive voice where you can use the active.
5. Never use jargon or a foreign phrase where an everyday word exists.
6. Break any rule before writing something ridiculous.

Do not use em dashes or these words: `comprehensive`, `robust`, `seamless`, `leverage`, `delve`, `streamline`.

Test each sentence: Would a busy engineer say it out loud? "Comprehensive error handling has been implemented" fails. "We added error handling to every API endpoint" passes.

Bring any prose you edit into line with these rules.
