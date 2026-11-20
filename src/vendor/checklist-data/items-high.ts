import type { ChecklistItem } from "./types.js";

export const ITEMS_HIGH: ChecklistItem[] = [
  {
    id: "error-monitoring",
    number: 23,
    title: "Get notified the moment something breaks",
    category: "Operations",
    priority: "high",
    timeEstimate: "30 min",
    prompt:
      "Act as a senior engineer. Install error monitoring across my full stack. Default to Sentry unless you have a strong reason to recommend otherwise — explain. Wire it into both frontend and backend. Configure: (1) automatic error capture for unhandled exceptions and rejected promises; (2) source maps so stack traces show real line numbers; (3) user context (user ID + email when available) so I can see who hit each error; (4) release tagging so I know which deploy introduced what; (5) noise filtering for browser extensions and common bot errors; (6) email/Slack alerts for new error types or sudden spikes; (7) performance/transaction tracing on my key routes. Test by deliberately throwing a test error in dev and confirming it shows up. List every env variable I need to set and tell me which dashboard settings to flip.",
    what: "Error monitoring is software that sits inside your app and silently records every error, then alerts you. So when your user hits a bug at 2am, you know about it within minutes \u2014 instead of hearing about it three days later from a frustrated tweet.",
    why: "Most users do not report bugs. They just leave. By the time you find out something is broken from feedback, dozens of people have already bounced. With error monitoring, you see problems immediately and can fix them before they spread.",
    steps: [
      "Sign up for Sentry (most popular, generous free tier), Rollbar, or PostHog.",
      "Install their SDK in both your frontend and backend (your AI builder can do this in one prompt).",
      "Connect it to email or Slack so new errors notify you.",
      "For the first week after launch, check the dashboard daily \u2014 fix recurring errors before they pile up.",
      "Configure it to ignore known noise (browser extensions, bots) so real signal stands out.",
    ],
    redFlags: [
      "The same error happening to dozens of users without anyone telling you",
      "Errors trending upward week over week",
      "Database connection failures showing up regularly",
      "No one has looked at the error dashboard in over a week",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found no error-monitoring or alerting wired into your app — no Sentry (or equivalent like Rollbar or PostHog) SDK in the frontend or backend. That means when a real user hits an exception, nothing records it and nothing tells you.",
      whyItBlocksLaunch:
        "Most users never report bugs — they just leave. Without error monitoring, a broken signup or a crashing checkout can quietly bounce dozens of people before you hear about it, and you'll usually hear it as a frustrated tweet three days later. On launch day, when traffic is highest, is the most expensive time to be flying blind.",
      fixInstructions:
        "Install an error-monitoring SDK (Sentry is the default choice, generous free tier) in both frontend and backend. Turn on automatic capture of unhandled exceptions and rejected promises, upload source maps so stack traces show real line numbers, attach user context (user ID + email) so you can see who hit each error, and tag releases so you know which deploy introduced a bug. Route new-error-type and spike alerts to email or Slack. Confirm it works by throwing a deliberate test error and watching it appear in the dashboard.",
      aiBuilderPrompt:
        "Install error monitoring across this app's full stack — default to Sentry unless you have a strong reason otherwise, and explain it. Wire it into both frontend and backend with: automatic capture of unhandled exceptions and promise rejections; source maps so traces show real line numbers; user context (ID + email when available); release tagging; noise filtering for browser-extension and bot errors; and email/Slack alerts on new error types or spikes. List every env var I need to set and which dashboard toggles to flip, then add a temporary throw-test-error route so I can confirm events arrive. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm `error-monitoring` is clean, then trigger the test error and confirm it lands in your monitoring dashboard within a minute, with a readable stack trace and the user context attached.",
    },
  },
  {
    id: "uptime-monitoring",
    number: 24,
    title: "Get pinged the moment your app goes completely down",
    category: "Operations",
    priority: "high",
    timeEstimate: "30 min",
    prompt:
      "Act as an SRE. Set me up with external uptime monitoring on my production URL (and any other critical surfaces — API health endpoint, login page, marketing site). Use Better Stack, UptimeRobot, or Pingdom — recommend one in 2 sentences. Configure: (1) check every 1-3 minutes from at least 3 geographic regions; (2) alerts to BOTH email and SMS / Slack — pick whatever I'll actually see at 2am; (3) require 2 consecutive failed checks before alerting (avoid false alarms from a single blip); (4) a public status page so users can self-serve when something is broken (most providers include this free); (5) add a simple /health endpoint to my backend that returns 200 + a timestamp + database connectivity check, so the monitor can verify more than just 'web server returns HTML'. Walk me through the dashboard step by step.",
    what: "An external service that pings your site every minute or so. If it ever fails to respond, you get a text or email within minutes — even at 3am. Different from error monitoring, which only works when your app is up enough to phone home.",
    why: "When your app is fully dead — server crashed, database unreachable, deployment broke — your error tracker can't tell you because it's also down or never sees the requests. The only thing that catches a total outage is something completely outside your stack pinging you from the outside. Most early-stage apps find out they're down from a customer complaint hours later.",
    steps: [
      "Sign up for UptimeRobot (free tier is fine for one site), Better Stack, or Pingdom.",
      "Add monitors for: your homepage, your login page, and a /health endpoint on your backend.",
      "Configure alerts to BOTH email and your phone (SMS or push) — pick whatever wakes you up.",
      "Add a /health endpoint to your backend that does a quick database query and returns 200 only if everything works. Otherwise the monitor will say 'up' even when the database is dead.",
      "Turn on the public status page (most providers include this free) and link to it from your footer or feedback widget — saves you from being flooded with 'is it down?' messages.",
    ],
    redFlags: [
      "You only know you're down when a user emails you",
      "Monitoring is set to 'check every hour' (way too slow for a real launch)",
      "Alerts go only to an email you check twice a day",
      "/health endpoint just returns 200 without actually checking the database",
      "No public status page — every outage = 100 'is it down?' messages",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "External uptime monitors live in a provider dashboard, not in the codebase. The scanner cannot prove the production URL is being checked from multiple regions or that alerts reach your phone.",
  },
  {
    id: "rate-limiting",
    number: 25,
    title: "Cap how often someone can hit your app",
    category: "Security",
    priority: "high",
    timeEstimate: "1 hr",
    prompt:
      "Act as a backend security engineer. Add rate limiting to every public-facing endpoint. Use a sensible default (60 req/min/IP) for normal public reads, around 100 req/min/IP for low-risk public utility endpoints, and tighter limits for sensitive ones: login (5 per 15 min per IP+email), signup (3 per hour per IP), password reset (3 per hour per email), OTP send (3-5 per hour per identifier), public forms (strict enough to stop spam), and AI/expensive endpoints (whatever fits a daily budget — ask me what I'm willing to spend per day). Return a clean 429 response with a Retry-After header and a friendly JSON message. Log every rate-limit hit with IP and route so I can see attacks. Use my framework's recommended middleware (express-rate-limit, hono-rate-limit, @upstash/ratelimit, Arcjet, etc.). Recommend in-memory vs Redis/Upstash backing based on whether I'm running multiple instances. After you're done, give me a curl one-liner I can run to verify it actually blocks me after N attempts.",
    what: "Rate limiting puts a maximum on how many requests one person (or one IP address) can make in a given window \u2014 say, 60 requests a minute. Without it, a single bot can hammer your backend until it falls over, run up your AI bill, or brute-force passwords until something works.",
    why: "Without rate limits you are one bad actor away from a $10,000 OpenAI bill, a crashed server, or a leaked password. Rate limits are cheap to add and save you from a long list of nightmares.",
    steps: [
      "Add rate limiting to every public-facing endpoint.",
      "Use stricter limits on the sensitive ones: login (5 per 15 minutes), signup (3 per hour), password reset (3 per hour), AI calls (whatever fits your budget).",
      "Use a shared backing store such as Redis/Upstash when the app runs more than one instance. In-memory limits reset per instance.",
      "Return a clear \"you're going too fast, try again in X seconds\" message \u2014 don't just silently fail.",
      "Watch for repeated rate-limit hits \u2014 they're usually attacks. Have alerts set up for spikes.",
      'Ask your AI builder: "add per-IP rate limiting to all my endpoints with stricter limits on login, signup, and password reset."',
    ],
    redFlags: [
      "No rate limits at all",
      "Same limits everywhere (login should be way stricter than browsing)",
      "Auth endpoints (login, signup, password reset) not strictly capped — brute-force and credential-stuffing bots will find you",
      "Rate limits are in-memory even though production runs multiple instances",
      "No alerting when someone repeatedly hits the limit",
      "You can't see how often this is happening",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found public endpoints — especially auth routes like login, signup, OTP, and password reset — with no rate limiting. Without it, one script can hammer those routes as fast as the network allows: guessing passwords, brute-forcing codes, or draining anything expensive behind them.",
      whyItBlocksLaunch:
        "Unlimited requests on auth routes is how accounts get brute-forced and how OTP/SMS or paid-API costs get run up. And a plain requests-per-minute limit isn't enough for token-priced AI endpoints — a few max-length requests can cost more than thousands of small ones, so cost-based abuse slips through an IP limit. This is a launch-day exposure the moment you have public traffic.",
      fixInstructions:
        "Add rate limiting to every public endpoint, with the strictest limits on auth (login, signup, OTP, reset) — e.g. a few attempts per identifier+IP per window. For AI or other paid endpoints, add identity-aware per-user daily budgets and per-request max-token caps on top of the IP limit, and require auth so no expensive route is anonymous. Return a clear 429 with Retry-After, and log/alert when someone repeatedly trips the limit.",
      aiBuilderPrompt:
        "Add rate limiting across this app. Put the strictest limits on auth routes (login, signup, OTP, password reset) keyed on identifier+IP, returning 429 with Retry-After. For any AI or paid endpoint, add identity-aware per-user daily quotas and per-request max-token caps in addition to IP limits, and require authentication. Add logging/alerting when a client repeatedly trips a limit. List each endpoint and the limit you set. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm zero findings under `rate-limiting`. Then script rapid repeated requests against your login/OTP endpoint and confirm you start getting 429s with a Retry-After header instead of unlimited attempts.",
    },
  },
  {
    id: "dependency-audit",
    number: 26,
    title: "Patch your dependencies for known vulnerabilities",
    category: "Security",
    priority: "high",
    timeEstimate: "30 min",
    prompt:
      "Act as a senior security engineer. Audit my project's installed dependencies for known vulnerabilities AND for supply-chain hygiene, and apply fixes. Tasks: (1) run the right auditor for my package manager — `npm audit` or `pnpm audit` for Node, `pip-audit` for Python, `bundle audit` for Ruby, `cargo audit` for Rust — and report the severity counts (critical / high / moderate / low). (2) for every Critical or High finding, try the auto-fix first (`npm audit fix`); if that doesn't clear it, upgrade the offending package manually and test the app after each change. Don't blindly `--force`. (3) if clearing a CVE needs a major-version bump that would break my app, document the CVE + the blocked upgrade + my exposure, then add a temporary mitigation if one's possible. (4) run or configure the builder/platform's built-in dependency/security scanner too, then compare its findings against the package-manager audit so nothing is silently ignored. (5) supply-chain hygiene — for every direct dependency, look up weekly download count and most-recent release date on the registry. Flag any dep with <1k weekly downloads (could be a typosquat — check the name against the obvious legitimate package) and any dep with no release in 12+ months (unmaintained — plan a replacement). (6) turn on automated dependency updates so this doesn't rot: Dependabot (free on GitHub) or Renovate — PR weekly for minor/patch, prompt on major. (7) add an audit step to my CI pipeline that fails the build on any new Critical CVE. When you're done, tell me plainly: any CVEs that made it to prod, any I deferred (with reasoning), any suspicious or abandoned deps I should swap, and the auto-update cadence you configured.",
    what: "Your app pulls in hundreds of third-party packages via `npm install` (or pip, bundle, cargo). Some of those packages have known security bugs with public write-ups and working exploits. Auditing means running one command to list every known bug in your dependencies, then upgrading to the fixed versions.",
    why: "Most successful attacks on small apps aren't clever — they're automated scanners finding sites that ship an old version of a popular library with a published CVE. The fix is usually a one-command upgrade. Skipping this is handing attackers the easiest version of your app.",
    steps: [
      "Run your package manager's audit command (`npm audit`, `pnpm audit`, `pip-audit`, `bundle audit`, `cargo audit`) and read the output.",
      "For every Critical or High finding, try the auto-fix first (e.g. `npm audit fix`). Test that the app still works after each fix.",
      "For fixes that require a major-version bump, read the package's upgrade notes before updating — breaking changes are real.",
      "If a CVE has no fix yet, at least know you have it. Document it and subscribe to the package's security advisories.",
      "Check your builder or hosting scanner output too. If Cursor, Claude Code, Lovable, Replit, GitHub, Snyk, or Semgrep flags dependency risk, reconcile it with the package audit.",
      "Turn on Dependabot or Renovate in your GitHub repo so it opens PRs as new versions ship — you're not manually checking anymore.",
      "Add the audit command to your CI pipeline so shipping a new Critical CVE breaks the build.",
    ],
    redFlags: [
      "You have never run `npm audit` (or your language's equivalent) on this project",
      "The audit shows Critical severity — and you shipped anyway",
      "Your builder or GitHub security tab shows warnings you have not read",
      "Dependabot / Renovate is not turned on",
      "Your lockfile hasn't been touched in more than 6 months",
      "CI never fails on a new CVE — you'll only find out from a bug report or a breach",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Dependency risk changes daily and needs the package manager plus registry advisories at scan time. Static checklist data cannot prove every critical CVE has been patched or consciously deferred.",
  },
  {
    id: "logging",
    number: 27,
    title: "Keep a paper trail of what your app is doing",
    category: "Operations",
    priority: "high",
    timeEstimate: "1 hr",
    prompt:
      "Act as a senior backend engineer. Set up structured JSON logging across my app using my framework's recommended logger (pino, winston, etc.). Log: every login, signup, logout, password change, payment event, admin action, and every error with full context (user ID, request ID, route, sanitized params). NEVER log passwords, tokens, full credit card numbers, full session IDs, or any PII beyond what's strictly necessary — implement a redaction list. Add request ID middleware so every log line in a single request can be correlated. Set log levels: debug only in dev, info+ in production. Send logs somewhere I can search (Logtail, Axiom, Datadog, or my platform's log viewer). After you're done, write me a short \"logging do/don't\" reference card to paste into my README.",
    what: "Logging is your app writing down what it did, when, and for whom \u2014 like a security camera for code. When something goes wrong (a charge failed, an account got locked, data is missing), good logs let you reconstruct exactly what happened. Bad logs leave you guessing.",
    why: "When you eventually have a weird bug or a user complaint that doesn't match what you see, logs are the difference between a 5-minute fix and a multi-day investigation. They're also your evidence if you ever have to prove what happened (security incident, billing dispute, abuse report).",
    steps: [
      "Use a structured logger (one that writes JSON, not raw text) \u2014 most frameworks have one built in.",
      "Log every login, signup, password change, payment, and important user action.",
      "Log every error with full context (which user, which endpoint, what they were doing).",
      "NEVER log passwords, API keys, full credit card numbers, or any other secret. This is itself a security incident waiting to happen.",
      "Keep logs for at least 30 days so you can investigate slow-burning issues.",
    ],
    redFlags: [
      "You're logging passwords or full personal info",
      "Errors in production with no log trail at all",
      "Logs are unstructured walls of text you can't search",
      "Logs disappear within a day",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Logging is only launch-ready if the right events arrive in a searchable production sink without secrets. The scanner cannot prove retention, redaction, or dashboard access from code alone.",
  },
  {
    id: "session-management",
    number: 28,
    title: "Make sessions feel safe AND convenient",
    category: "Security",
    priority: "high",
    timeEstimate: "1 hr",
    prompt:
      'Act as a security engineer. Audit and improve my session management. Verify and fix: (1) sessions expire after 24h of inactivity; (2) password change invalidates ALL existing sessions for that user, not just the current one; (3) there\'s a "log out everywhere" button in account settings that actually works; (4) sessions are stored server-side (or as signed/encrypted JWTs with a short TTL plus refresh tokens) — never plaintext cookies; (5) session IDs rotate on login to prevent session fixation; (6) if I use JWTs, verify the verifier explicitly allowlists the signing algorithm (HS256 or RS256) and REJECTS tokens where alg is "none" or differs from what I signed with — algorithm-confusion attacks are a common JWT foot-gun. Verify the signing key is at least 256 bits of real randomness (not "secret" or "changeme") and comes from an env var, not a literal; (7) optional but recommended: show users a list of active sessions with device, IP, and last activity, with the ability to revoke any. Implement the changes, then explain each one in a plain-English sentence so I understand what changed and why.',
    what: "How you handle \u201Cis this person still logged in?\u201D over time. Get this right and users stay logged in long enough to be useful, but not so long that a forgotten laptop becomes a permanent risk.",
    why: "Bad session handling is either annoying (kicked out every 20 minutes) or dangerous (still logged in three months later on a shared computer). The right defaults make both rare.",
    steps: [
      "Set sessions to expire after a reasonable window of inactivity (12\u201324 hours is normal).",
      'Add a "Remember me" checkbox if you want longer sessions \u2014 but only when explicitly chosen by the user.',
      "When a user changes their password, log out all their other sessions automatically.",
      'Give users a "log out everywhere" button in their account settings.',
      "If your auth provider supports it, show users where they're currently logged in (device, IP, last activity).",
    ],
    redFlags: [
      "Sessions that never expire",
      "Changing your password doesn't kick out other sessions",
      "No way for a user to see or end their other sessions",
      'Insecure "Remember me" (a long-lived plaintext token in a cookie)',
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found session or cookie-hardening gaps — session cookies missing HttpOnly, Secure, or SameSite; sessions that never expire; or a JWT setup that doesn't pin the signing algorithm (leaving the door open to an alg:none or algorithm-confusion attack) or uses a weak/literal signing secret.",
      whyItBlocksLaunch:
        "Weak sessions cut both ways: too loose and a forgotten laptop or a stolen cookie is a permanent account takeover; a JWT verifier that accepts alg:none lets an attacker forge a valid-looking token with no key at all. A cookie without HttpOnly can be read by any injected script; without Secure it can leak over plain HTTP. These are invisible until someone exploits them.",
      fixInstructions:
        "Set session cookies HttpOnly, Secure, and SameSite=Lax (or Strict). Expire sessions after ~24h of inactivity, and rotate the session ID on login to prevent fixation. Invalidate all of a user's sessions on password change, and add a log-out-everywhere control. If you use JWTs, make the verifier explicitly allowlist your signing algorithm (HS256 or RS256) and reject alg:none or any mismatch; use a signing key of at least 256 bits of real randomness from an env var, never a literal like changeme.",
      aiBuilderPrompt:
        "Audit and harden this app's session management. (1) Set all session cookies HttpOnly + Secure + SameSite=Lax. (2) Expire sessions after 24h of inactivity and rotate the session ID on login. (3) Invalidate ALL of a user's sessions on password change, and add a working log-out-everywhere button. (4) If JWTs are used, make the verifier allowlist exactly one algorithm (HS256 or RS256) and reject alg:none or any mismatch; confirm the signing secret is 256+ bits of real randomness from an env var, not a literal. Explain each change in one plain-English sentence. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm `session-management` is clean, then in dev tools under Application → Cookies confirm your session cookie shows HttpOnly, Secure, and SameSite set, and that changing your password logs out your other sessions.",
    },
  },
  {
    id: "github",
    number: 29,
    title: "Connect to GitHub for backups and history",
    category: "Infrastructure",
    priority: "high",
    timeEstimate: "30 min",
    prompt:
      "Act as a developer-tooling expert. Walk me through connecting this project to a private GitHub repo step by step, in the simplest possible way for someone who has never used git from the command line. Then: (1) audit existing git history for any committed secrets and tell me which ones need to be rotated; (2) generate a complete .gitignore tuned to my exact stack (no .env, no build artifacts, no local DBs, no .DS_Store, no IDE folders); (3) verify nothing sensitive is currently being tracked; (4) set up a CODEOWNERS file with my GitHub username as default owner; (5) add a basic GitHub Actions workflow that runs my linter, typecheck, and tests on every push and PR. Explain each command in plain English BEFORE I run it.",
    what: "GitHub is an external service that stores every version of your code, forever. Even if your project on your builder gets deleted, broken, or accidentally rolled back too far, GitHub has every version you ever pushed. It's also how anyone else (a co-founder, a contractor) collaborates with you.",
    why: "Most builders have their own undo/checkpoint history, but having your code in a second place is one more disaster you'll never have. Plus: when you eventually want to hire a real developer, the first thing they'll ask is \"can I have GitHub access?\"",
    steps: [
      "Create a free GitHub account if you don't have one.",
      "In your builder, connect your project to a new GitHub repository \u2014 most have a one-click GitHub button in their Git or Version Control pane.",
      "Make the repo private if your code includes business logic you don't want copied.",
      "Confirm your secrets are NOT being pushed. Most builders exclude their secrets store by default, but double-check there's no .env file or hardcoded key leaking through. If anything sensitive made it in, rotate the keys at the source service immediately.",
      "Push regularly \u2014 at least daily, ideally after every meaningful change.",
    ],
    redFlags: [
      "No version control at all (your only copy lives inside one builder)",
      "Secrets accidentally pushed to the repo",
      "You haven't pushed in days \u2014 you could lose work to one bad rollback",
      "Public repo containing private business logic or customer data",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found no connection to a private GitHub remote — your project has no off-platform backup or version history. If it lives only inside your builder, there's exactly one copy.",
      whyItBlocksLaunch:
        "If your builder account gets deleted, your project breaks, or a rollback goes one step too far, GitHub is the second place that still has every version you ever pushed. Without it, one bad day can erase the whole project. It's also the first thing any developer you hire will ask for.",
      fixInstructions:
        "Create a private GitHub repo and connect your project — most builders have a one-click GitHub button in their version-control pane. Before you push, generate a .gitignore tuned to your stack so no .env, build artifacts, local DBs, or .DS_Store get committed, and confirm nothing sensitive is already tracked. If any secret ever made it into history, rotate it at the source service — removing it from the latest commit doesn't remove it from history. Then push regularly, at least daily.",
      aiBuilderPrompt:
        "Connect this project to a private GitHub repo, explained simply for someone who's never used git from the command line. (1) Generate a complete .gitignore tuned to my exact stack — exclude .env, build artifacts, local DBs, .DS_Store, and IDE folders. (2) Audit current git history for any committed secrets and list which ones I need to rotate at the source. (3) Verify nothing sensitive is currently tracked. (4) Walk me through creating the private repo and pushing, explaining each command in plain English before I run it. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm `github` is clean, then open your repo on github.com and confirm it's private, shows your latest code, and contains no .env file or hardcoded keys.",
    },
  },
  {
    id: "rollback",
    number: 30,
    title: "Know how to roll back a bad deploy in under a minute",
    category: "Operations",
    priority: "high",
    timeEstimate: "15 min",
    prompt:
      "Act as a deployment engineer. For my specific hosting platform, walk me through the EXACT click-by-click procedure to roll back to the previous deploy. Then have me actually do it once — to a previous commit, then forward again — so I know the muscle memory before I need it. Also: (1) tell me what's preserved during a rollback (env variables, secrets, data) and what isn't (any DB migration that ran on the bad deploy is NOT undone — call this out); (2) recommend whether I should enable preview deployments on every PR/branch so I can test changes before they hit production; (3) give me a 5-line emergency runbook (ROLLBACK.md) I can paste into my repo: 'If production is broken, do these 3 things in this order.'",
    what: "The ability to undo a deployment in 30 seconds and get back to the last known good version. Almost every modern host supports one-click rollback to any prior version — but you need to know where the button is BEFORE the bad deploy.",
    why: "You will ship something broken to production. Your AI builder will help you 'fix' something at midnight and the fix will be worse. The difference between a 30-second outage and a 3-hour incident is whether you've practiced rolling back once when nothing was wrong.",
    steps: [
      "Find the Deployments or Releases panel in your hosting platform (most have 'Promote to production' or 'Rollback' next to each version).",
      "Do a practice rollback NOW, while everything is fine. Roll back one version, confirm the site still works, then roll forward again. You want this in muscle memory.",
      "Understand what rollback does NOT undo: any database migration that ran on the bad version is still applied — your code is rolled back but your schema isn't. Plan accordingly (migrations should be backwards compatible).",
      "Turn on preview deployments so every change gets a temporary URL you can test before it touches production.",
      "Write a 5-line ROLLBACK.md in your repo: '1. Open hosting dashboard. 2. Find latest known-good version. 3. Click Rollback. 4. Verify site works. 5. Tell users in status page / Twitter what happened.'",
    ],
    redFlags: [
      "You don't know where the rollback button is in your hosting dashboard",
      "You've never actually performed a rollback even once",
      "All your changes go straight to production without a preview deployment",
      "Database migrations run automatically and are not reversible",
      "No written runbook — at 2am you'll be improvising under pressure",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Rollback readiness is muscle memory in the hosting dashboard plus a real recovery path for data migrations. The scanner cannot prove you practiced rollback and forward again.",
  },
  {
    id: "soft-launch",
    number: 31,
    title: "Soft-launch to 5 friends before you launch publicly",
    category: "Product & Launch",
    priority: "high",
    timeEstimate: "1 hr",
    prompt:
      "Act as a product launch coach. Help me set up a soft launch to 5-10 friends/early users 48 hours before my public launch. Output: (1) a short personal outreach message I can DM each one — friendly, asks a specific favor, sets expectations; (2) a one-page 'try this' brief: signup flow → core feature → one specific thing to try; (3) a feedback capture template (Google Form or Typeform) with 5 sharp questions: what was confusing, what was broken, what would you tell a friend it does, would you actually use this and why, on a scale of 1-10 how likely to recommend; (4) a 'watch them use it' protocol if I can get 1-2 of them on a screen-share — what to watch for, what to NOT do (don't help, don't explain, don't apologize); (5) a triage rubric for sorting their feedback into 'must fix before public launch' vs 'next week' vs 'never'. Be ruthless about scope — this is 48 hours, not 4 weeks.",
    what: "Send your app to 5-10 friends or early users 1-3 days before the public launch and watch what happens. Not for moral support — for finding the obvious things you've gone blind to from staring at it for two weeks.",
    why: "This is the highest-leverage and cheapest item on the entire list. Five strangers will find five things you missed: the signup form that breaks on Safari, the button labeled 'Submit' that should be 'Save', the empty state that looks like a broken page. Catching these now costs an hour. Catching them on launch day in front of a thousand strangers costs your reputation.",
    steps: [
      "Make a list of 5-10 people who match your target user (not just supportive friends — actual matches). Include at least 2 who will be a little brutal.",
      "Send each one a personal message (NOT a group blast) 48 hours before launch. Tell them what to try, what kind of feedback you want, how long it'll take, and that 'this is broken' is the most useful thing they can say.",
      "If you can, get 1-2 on a screen-share. Watch silently. Don't help, don't explain, don't apologize. Where they hesitate is your bug list.",
      "Collect feedback in one place (a Google Form or shared doc), not scattered DMs. Easier to spot patterns.",
      "Sort the feedback into three buckets: must-fix-before-launch, do-in-week-1, never. Be ruthless — most public launches fail because the founder tried to fix everything in 48 hours and burned out.",
    ],
    redFlags: [
      "Going straight to public launch without anyone outside your head ever using it",
      "Only sending to people you know will love it (selection bias = useless feedback)",
      "Helping users when they get stuck instead of letting them struggle (you can't be there on launch day)",
      "Trying to 'fix everything' from soft launch — you'll miss public launch and burn out",
      "Feedback scattered across 10 DMs and a notebook — patterns are invisible",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "A soft launch is evidence from real humans, not a deploy artifact. The scanner cannot prove five target users tried the product and found the launch-day friction.",
  },
  {
    id: "interviews",
    number: 32,
    title: "Talk to your first 10 users on a real call",
    category: "Growth",
    priority: "high",
    timeEstimate: "2 hr+",
    prompt:
      "Act as a customer research expert in the style of Rob Fitzpatrick (The Mom Test). Help me prep for my first 10 user interview calls. Output: (1) a 15-minute interview script with 8-10 open-ended questions designed to surface real behavior and real pain — NOT to validate my product. Explicitly avoid leading questions like \"don't you love…?\"; (2) an outreach email template I can personalize and send to early signups, offering a $20 gift card; (3) a calendar-friendly question set; (4) a one-page note-taking template that captures the user's actual words verbatim, not my interpretation; (5) a synthesis template I can use after 5+ interviews to spot patterns across calls. Before generating anything, ask me what my product does, who the users are, and what I'm trying to learn — so the script is sharp, not generic.",
    what: "A 15-minute video or phone call with each of your first early users. Not a survey. Not a Slack DM. An actual conversation where you mostly listen.",
    why: "Data tells you what people do. Conversations tell you why. You'll find out which features confused them, which ones they actually use, and which problem they'd pay to solve. You can't guess your way to that.",
    steps: [
      "Reach out personally to your first 10\u201320 signups. Offer a $20 gift card if it helps (it does).",
      "Schedule 15 minutes \u2014 keep it short so people actually show up.",
      'Ask open questions: "Walk me through how you discovered us." "What were you trying to do when you signed up?" "What almost made you leave?"',
      "Listen way more than you talk. Don't defend the product, don't pitch. Take notes.",
      "After 5\u201310 calls, look for patterns. Those are your roadmap.",
    ],
    redFlags: [
      "You've never actually talked to a user out loud",
      "You only talk to people who already love it (selection bias)",
      'You ask leading questions ("don\'t you love that we did X?")',
      "You spend the call defending your decisions instead of listening",
      "No notes \u2014 insights evaporate the moment the call ends",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Customer interviews are a research practice with real conversations and notes. The scanner can never tell whether ten users said the pain out loud in their own words.",
  },
  {
    id: "onboarding",
    number: 33,
    title: "Make the first 5 minutes obvious",
    category: "Product & Launch",
    priority: "high",
    timeEstimate: "2 hr+",
    prompt:
      "Act as a senior product designer focused on first-run onboarding. Audit my app from the perspective of a brand-new user who has never seen it before. Create a fresh account and walk the first 5 minutes. Verify and fix: (1) the landing page tells me exactly what to do next; (2) signup does not ask for anything unnecessary before value; (3) the first logged-in screen has one obvious next action, not a dead empty state; (4) sample data, templates, or guided setup exist if the product is blank by default; (5) every permission, integration, or setup step explains why it is needed; (6) the user reaches a real 'aha' moment or useful artifact within 5 minutes. Output a friction log with timestamp, screen, what confused me, and the smallest fix. Then implement the top 3 fixes without redesigning the whole app.",
    what: "The first 5 minutes are the difference between 'I get it' and 'I'll come back later' (they won't). A new user needs one clear path from landing page to signup to first value, even if their account starts with no data.",
    why: "Vibe-coded apps often work only for the founder because the founder already knows what every blank page means. New users see an empty dashboard, a generic 'Get started' button, or a setup maze and assume the app is broken. You do not need fancy onboarding. You need the next action to be obvious.",
    steps: [
      "Create a brand-new account with an email that has never touched the app. Do not use your founder/admin account.",
      "Start a timer and try to get to first value in 5 minutes: a saved result, a generated output, a created project, a shared link, whatever your app promises.",
      "Make the first logged-in screen intentional. If there is no data yet, show an empty state with one clear action, not a blank dashboard.",
      "Add sample data, templates, import prompts, or a 3-step setup checklist if the product needs context before it can be useful.",
      "Watch one person do this without explanation. Where they pause, click randomly, or ask 'what now?' is the bug list.",
    ],
    redFlags: [
      "The first logged-in page is empty with no obvious next action",
      "Users have to configure integrations before understanding the product",
      "Signup asks for a long profile before the user sees value",
      "Buttons say vague things like 'Continue' or 'Submit' when the action should be specific",
      "You cannot explain what first value looks like in one sentence",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "First-run onboarding is a human walkthrough from fresh account to first value. The scanner cannot prove a brand-new user understands what to do in the first five minutes.",
  },
  {
    id: "dependency-integrity",
    // number assigned by the index.ts assembly (position-based)
    number: 0,
    title: "Confirm every package your AI added is real",
    category: "Security",
    priority: "high",
    timeEstimate: "30 min",
    prompt:
      "Act as a supply-chain security engineer. AI coding tools sometimes invent package names that don't exist, and attackers pre-register those exact names with malicious code (this is called slopsquatting). Go through my dependencies and catch it. (1) List every package in my package.json / requirements.txt / lockfile. (2) For each one, verify it actually exists on the real registry and is the package I think it is — check its publish date, weekly download count, and maintainer. (3) Flag anything suspicious: a name that looks like a mashup of two real libraries, a near-miss spelling of a popular package, a package published very recently with almost no downloads, or one you don't remember adding. (4) For anything I don't actually use, remove it. (5) Pin my lockfile so the exact versions are locked. Give me a short report — real / verify / remove — for each dependency, and don't install or change anything until I approve.",
    what: "AI builders sometimes 'hallucinate' a package — they confidently import a library name that doesn't exist. Attackers have figured out which fake names the AIs invent most often and registered those names with malicious code, so when you (or your AI) run install, you get the attacker's package instead of a helpful one.",
    why: "This is a real, growing attack aimed squarely at AI-built apps. Studies found roughly a fifth of AI-recommended packages don't exist, and the same fakes get suggested over and over — predictable enough for attackers to camp on. In late 2025 a self-propagating malicious package spread through hundreds of repos this way, with nobody deliberately installing it. A regular vulnerability scanner won't catch it, because a brand-new malicious package has no known-vulnerability history yet.",
    steps: [
      "List every dependency in your package.json / requirements.txt / go.mod and your lockfile.",
      "For each one, confirm it exists on the real registry and looks legitimate — reasonable download counts, a real maintainer, a publish history, not a package created last week with 12 downloads.",
      "Be suspicious of names that are one character off a popular package, or that look like two real libraries mashed together.",
      "Remove any dependency you don't actually use — every extra package is extra risk.",
      "Pin your lockfile (commit package-lock.json / pnpm-lock.yaml / yarn.lock) so the exact resolved versions are locked and can't silently change.",
      "When your AI suggests a new package, look it up before installing it — don't let the agent install a name neither of you has verified.",
    ],
    redFlags: [
      "A dependency name that's a near-miss of a popular one (e.g. one letter off, or two real libraries mashed together)",
      "A package with almost no downloads or a maintainer you can't find",
      "Dependencies in your manifest you don't remember adding and don't use",
      "No committed lockfile, so installs can resolve to different versions over time",
      "Letting an AI agent install packages without anyone verifying they're real",
    ],
    references: [
      {
        label: "CSA research note on slopsquatting",
        url: "https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419-csa/",
      },
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner flagged a dependency whose name looks invented, typo-squatted, or like a mashup of two real libraries. AI coding tools hallucinate package names that don't exist, and attackers pre-register those exact names with malicious code — so a name that's a near-miss of a popular package is worth verifying before you trust it.",
      whyItBlocksLaunch:
        "If the flagged package is a squatted name, installing it runs attacker-controlled code inside your app and build with your permissions — a direct path to stolen secrets or a compromised deploy. Regular vulnerability scanners miss this because a freshly-registered malicious package has no known-vulnerability history yet, so this is exactly the check that catches it.",
      fixInstructions:
        "For the flagged dependency, confirm on the real registry that it exists and is the package you intended: check its publish date, weekly downloads, and maintainer. If it's a typo of a real package, remove it and install the correct name. If it's a package you don't actually use, remove it entirely. Then pin your lockfile so resolved versions can't silently change, and treat any AI-suggested package as unverified until you've looked it up.",
      aiBuilderPrompt:
        "Review the dependency the shippingszn scanner flagged under `dependency-integrity`, plus every other package in my manifest and lockfile. For each: tell me whether it exists on the real registry, its publish date, weekly downloads, and maintainer, and whether the name looks like a typo or mashup of a popular package. Recommend real / verify / remove for each. Remove packages I don't use, fix any typo-squatted name to the correct package, and pin the lockfile. Do not install anything until I approve — show me the report and the diff first.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm zero findings under `dependency-integrity`. Manually open the flagged package's registry page (npmjs.com / pypi.org) and confirm it's the real, maintained project you intended — not a look-alike registered recently.",
    },
  },
  {
    id: "agent-ci-security",
    number: 0,
    title: "Lock down the AI agents you wired into your repo or CI",
    category: "Security",
    priority: "high",
    timeEstimate: "1 hr",
    prompt:
      "Act as a CI/CD security engineer. I may have connected an AI coding agent to my repo or pipeline (Claude Code Action, a background/cloud agent, a bot that responds to issues or PRs). Audit that setup for the pattern that leaks secrets. The rule of two: an agent must never simultaneously (a) read untrusted input like a public issue, PR, or web page, (b) hold live secrets, and (c) have write or publish access. For every AI agent wired into my repo: tell me what untrusted input it can read, what secrets it can reach, and what it can write or deploy. Flag any that hold all three. Then: pin every GitHub Action to a full commit SHA (not a floating tag), scope every token to the minimum it needs, remove any permission-bypass flags (--yolo, --dangerously-skip-permissions, --trust-all-tools), and require a human diff review before any agent can auto-merge or deploy to production. Give me the specific config changes; don't apply anything until I approve.",
    what: "If you connected an AI agent to your repo or CI — something that reads issues/PRs and can make changes — it can be tricked. A hidden instruction planted in a public issue or PR can hijack the agent into reading your secrets and leaking them, because the agent runs with your access.",
    why: "This is a real, disclosed 2026 attack class, not theory. A hidden instruction in a public GitHub issue made a popular CI coding agent read its environment and leak an API key (rated critical severity); a separate July 2026 flaw tricked repo agents into exfiltrating private repositories; and supply-chain malware has invoked local AI CLIs with permission-bypass flags to hunt for credentials. The common thread: an agent that can read untrusted text, holds secrets, and can write is an exfiltration path.",
    steps: [
      "Inventory every AI agent connected to your repo or CI: what triggers it, what it can read, what secrets it can reach, what it can write or deploy.",
      "Apply the rule of two: never let one agent read untrusted input (public issues/PRs, scraped web, user content) AND hold live secrets AND have write/publish access at the same time. Break at least one leg.",
      "Pin every GitHub Action to a full commit SHA, not a moving tag like @v1.",
      "Scope tokens to least privilege; never expose the agent's own API keys in its context or logs.",
      "Ban permission-bypass flags (--yolo, --dangerously-skip-permissions, --trust-all-tools) in anything that runs against real credentials.",
      "Require a human diff review before an agent can merge or deploy to production — no silent auto-merge from an untrusted trigger.",
    ],
    redFlags: [
      "An agent that responds to public issues/PRs and also holds secrets and can push or deploy",
      "GitHub Actions pinned to floating tags (@v1, @latest) instead of a commit SHA",
      "Permission-bypass flags used in CI or against a repo with real credentials",
      "An agent that can auto-merge or auto-deploy with no human review",
      "The agent's own API key visible in its context, logs, or environment it will print",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Agent-in-CI risk lives in your pipeline config, trigger permissions, and token scopes across GitHub/CI, not in your app source. Proving an agent can't reach secrets while reading untrusted input is a configuration audit the scanner can't perform.",
  },
  {
    id: "mcp-security",
    number: 0,
    title: "Secure any MCP server your app exposes or consumes",
    category: "Security",
    priority: "high",
    timeEstimate: "1 hr",
    prompt:
      "Act as an agent-security engineer. My app may expose an MCP (Model Context Protocol) server, or consume third-party MCP servers/tools. Harden both directions. If I EXPOSE an MCP server: require authentication (OAuth 2.1 with PKCE), validate the token audience, never forward a client's token upstream, allow-list and validate every tool input, block requests to private/internal IPs (SSRF), and put sensitive tools behind a human-confirmation step. If I CONSUME MCP servers or tools: pin the exact package/version, review the diff on every update, treat every third-party tool description as untrusted input (a poisoned description can hijack the agent), and never auto-update tooling that can send mail or move data. List every MCP endpoint and tool in my project, tell me which direction each is, and give me the specific fix for each. Don't change anything until I approve.",
    what: "MCP is how AI agents connect to tools and data. If your app exposes an MCP server, it's an API that can drive real actions — and many ship with no authentication. If your app consumes third-party MCP tools, a malicious or hijacked tool can turn your agent against you.",
    why: "This surface barely existed a year ago and is now actively attacked. 2026 audits found a large share of remote MCP servers expose tools with no auth and handle credentials in plaintext; a trusted MCP email package turned malicious in a routine version bump and silently BCC'd every message to an attacker; and 'tool poisoning' — hidden instructions in a tool's description — succeeded against agents at high rates. If you expose or consume MCP, it needs the same care as a payment integration.",
    steps: [
      "List every MCP server your app exposes and every third-party MCP server or tool it consumes.",
      "For servers you expose: require OAuth 2.1 + PKCE, validate the token audience, and never leave an MCP endpoint unauthenticated.",
      "Validate and allow-list every tool input; block tool calls that fetch private/internal IPs (SSRF).",
      "Gate sensitive or irreversible tools behind an explicit human-confirmation step.",
      "For tools you consume: pin exact versions, review the diff on every update, and treat every third-party tool description as untrusted input.",
      "Never auto-update agent tooling that can send email or move data — vet the publisher like a payment SDK.",
    ],
    redFlags: [
      "An MCP endpoint reachable with no authentication",
      "Client tokens forwarded upstream, or token audience never validated",
      "Third-party MCP tools installed on a floating version with no diff review on updates",
      "Sensitive tools (send money, send email, delete data) with no human confirmation",
      "Tool descriptions from third parties trusted as safe instructions to the agent",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "MCP auth, token-audience validation, and tool-poisoning exposure depend on runtime configuration and the third-party tools you connect — the scanner can't authenticate to your MCP endpoints or judge whether a tool description is malicious.",
  },
];
