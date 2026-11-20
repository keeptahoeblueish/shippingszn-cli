import type { ChecklistItem } from "./types.js";

export const ITEMS_CRITICAL_B: ChecklistItem[] = [
  {
    id: "https-headers",
    number: 8,
    title: "Force HTTPS and add browser-level defenses",
    category: "Security",
    priority: "critical",
    timeEstimate: "1 hr",
    prompt:
      "Act as a security engineer. Set my app up with production-grade security headers. Add: Strict-Transport-Security (HSTS) with includeSubDomains and a 1-year max-age once I'm confident; Content-Security-Policy tuned to the actual scripts/styles/images/fonts/connections my app uses (no wildcards, no unsafe-inline unless I explicitly approve it — list each exception with a justification); X-Content-Type-Options: nosniff; X-Frame-Options: DENY (or SAMEORIGIN if I embed my own pages — ask me); Referrer-Policy: strict-origin-when-cross-origin; Permissions-Policy disabling features I don't use (camera, microphone, geolocation, etc.). Add an application-level http→https redirect as a backup to platform HTTPS. After you're done, tell me what to test at securityheaders.com and what grade I should expect.",
    what: "HTTPS is the little padlock in the browser bar. It encrypts everything between your user and your server, so people sharing the same WiFi can't read passwords as they're being typed. Security headers are extra instructions you send to the browser saying “never trust content claiming to be from me unless it really is.”",
    why: "Without HTTPS, anyone on the same coffee-shop WiFi can read your users' passwords as plaintext. Without security headers, attackers can wrap your site inside theirs (clickjacking) or trick browsers into running malicious scripts. The fixes are basically free.",
    steps: [
      "Most modern hosting gives you HTTPS automatically when you publish — confirm the lock icon shows up in the browser bar.",
      "Set up an automatic redirect from http:// to https:// so no one accidentally lands on the unencrypted version.",
      "Add a Content-Security-Policy header that locks down where your scripts, images, and fonts are allowed to come from.",
      "Add X-Content-Type-Options: nosniff and X-Frame-Options: DENY (or SAMEORIGIN if you embed your own pages).",
      "Test your site at https://securityheaders.com — aim for at least an A grade.",
    ],
    redFlags: [
      "Any page on your site that loads over plain http:// in production",
      "A grade of D or F on securityheaders.com",
      "Other websites can put your app in an iframe (potential clickjacking)",
      "Browser console shows mixed-content warnings",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found that your app is missing one or more browser security headers — HSTS, Content-Security-Policy, X-Frame-Options, or X-Content-Type-Options — or is reachable over plain HTTP. These headers are how a page tells the browser to defend itself; without them, a small bug or a third-party script has a much wider blast radius.",
      whyItBlocksLaunch:
        "Missing headers are exactly what automated scanners and attackers look for first, and a public grade of D or F on securityheaders.com is a bad look the moment anyone checks. Without a Content-Security-Policy, one injected script can run freely; without clickjacking protection, another site can frame your app and trick your users into actions they didn't intend.",
      fixInstructions:
        "Force HTTPS and redirect all HTTP traffic. Add these response headers at your host or app server: Strict-Transport-Security with a long max-age, a Content-Security-Policy scoped to your real asset origins (no wildcards, minimal unsafe-inline), X-Frame-Options: DENY (or frame-ancestors 'none' in CSP), and X-Content-Type-Options: nosniff. Tune the CSP to your actual scripts/styles/images so nothing legitimate breaks.",
      aiBuilderPrompt:
        "Add production security headers to this app. Force HTTPS and redirect HTTP. Set Strict-Transport-Security (long max-age, includeSubDomains), a Content-Security-Policy allow-listing only my real asset origins (no wildcards, justify any unsafe-inline), X-Frame-Options: DENY or frame-ancestors 'none', X-Content-Type-Options: nosniff, and a sensible Referrer-Policy. Show me the resulting header set and the CSP you chose, and confirm no legitimate scripts/styles/images are blocked. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm zero findings under `https-headers`. Then load the deployed site, open dev-tools Network, and confirm the response includes HSTS, CSP, X-Frame-Options, and X-Content-Type-Options — or check the URL on securityheaders.com and confirm at least an A grade.",
    },
  },
  {
    id: "dev-prod-data",
    number: 9,
    title: "Keep your test data away from real users",
    category: "Infrastructure",
    priority: "critical",
    timeEstimate: "30 min",
    prompt:
      'Act as a senior infrastructure engineer. Audit my project to confirm development and production are properly separated. Verify: (1) my dev workspace connects to a dev database, NOT production; (2) my production deployment uses production-only environment variables; (3) seed scripts, fixtures, and mock data are excluded from production; (4) destructive scripts (drop tables, wipe data, factory reset) cannot run in production by accident — add an explicit guard that fails if NODE_ENV is "production" unless I pass a confirmation flag; (5) any analytics/error monitoring is properly tagged by environment so I can tell dev noise from real production events. Tell me exactly which database my code reads from in each context. If anything is misconfigured, fix it and explain in plain English what was wrong.',
    what: "Two databases: one to mess around with while you build (development), one that holds your actual users' actual data (production). They should never touch each other. Most modern builders and hosted database services (Replit, Supabase, Neon, PlanetScale) set you up with both automatically when you publish.",
    why: "If you point a half-broken in-progress feature at the real database, you can corrupt or wipe real user data with one bad query. If you copy real user data into your dev environment, you've taken a privacy obligation and made it more likely to leak. Keep them apart.",
    steps: [
      "Know which is which: the database in your workspace is dev. The one your published app uses is prod.",
      "Never paste production database credentials into your dev workspace.",
      "When testing destructive features (delete account, bulk update, mass email), only test against dev data.",
      "If you ever need a slice of prod data for debugging, scrub names, emails, and any personal info first.",
      "Read your platform's docs on production databases so you know how to push schema changes (new tables, renamed columns) safely. Most have a one-page guide — the link below is Replit's, as one example.",
    ],
    redFlags: [
      'You can\'t answer "which database is my live app reading from right now?"',
      "Your in-progress code points at the production database",
      'You manually edit production data ("just one quick fix") with no rollback plan',
      "You've copied real production data to your dev environment without scrubbing",
      "Schema changes (new tables, renamed columns) go live without ever being tested first",
    ],
    references: [
      {
        label: "Example: Replit production databases",
        url: "https://docs.replit.com/cloud-services/storage-and-databases/sql-database",
      },
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found signs that development and production aren't cleanly separated — a database URL that looks shared between dev and prod, seed/fixture/mock data reachable in the production build, or a destructive script (drop, truncate, reset, wipe, seed) with no guard stopping it from running against production.",
      whyItBlocksLaunch:
        "If your in-progress code points at the real database, one bad query while you're building can corrupt or wipe live user data. An unguarded reset or seed script is even worse — one accidental run in production and real accounts are gone. And copying real user data into your dev environment quietly turns a privacy obligation into a leak waiting to happen.",
      fixInstructions:
        "Confirm your dev workspace reads a dev database and production reads a production-only connection string — never the same one. Exclude seed scripts, fixtures, and mock data from the production build. Add an explicit guard to every destructive script that hard-fails when NODE_ENV is 'production' unless you pass an explicit confirmation flag. Tag analytics and error monitoring by environment so dev noise never mixes with real production events. If you ever pull a slice of prod data to debug, scrub names, emails, and any PII first.",
      aiBuilderPrompt:
        "Audit this project for dev/prod data separation. (1) Tell me exactly which database each context connects to, and confirm dev and prod use different connection strings sourced from env vars, never a shared literal. (2) Make sure seed scripts, fixtures, and mock data are excluded from the production build. (3) Add a guard to every destructive script (drop/truncate/reset/wipe/seed) that throws and exits if NODE_ENV is 'production' unless I pass an explicit --confirm-prod flag. (4) Tag analytics and error monitoring by environment. Explain in plain English anything you found misconfigured. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm `dev-prod-data` is clean, then try running a destructive script with NODE_ENV=production and confirm it refuses to run without the explicit confirmation flag.",
    },
  },
  {
    id: "backups",
    number: 10,
    title: "Back up your database — and actually test the restore",
    category: "Infrastructure",
    priority: "critical",
    timeEstimate: "1 hr",
    prompt:
      "Act as a senior infrastructure engineer. Tell me, for my specific database setup, exactly: (1) is automatic point-in-time backup turned on, and how far back can I restore? (2) where the backups physically live and who can access them; (3) the EXACT click-by-click procedure to restore my database to a point 24 hours ago in a non-destructive way (clone first, swap if good, never restore in place blind). Then walk me through ACTUALLY DOING a test restore right now to a clone — not in theory, in practice — so I know it works before I need it. Also recommend an additional manual backup strategy (weekly export to object storage I control) so I'm not 100% dependent on my host. Output a one-page DISASTER_RECOVERY.md I can keep with my project.",
    what: "An automatic, recent copy of your entire database stored somewhere safe — and the ability to restore from it without guessing under pressure. Most managed databases (Neon, Supabase, Replit DB, RDS, PlanetScale) include some form of backup, but defaults vary, and 'a backup exists' is not the same thing as 'a backup that works.'",
    why: "Sooner or later you, your AI builder, or a script will run the wrong query against the production database. Without a tested backup, your only options are 'rebuild from memory' and 'apologize to users in public.' With one, it's a 10-minute fix. The whole point of doing this BEFORE launch is that nobody is depending on the data yet — so testing the restore is free.",
    steps: [
      "Open your database's dashboard (Neon, Supabase, Replit, etc.) and find the Backups or Point-in-time Recovery section. Confirm automatic backups are on, and note how many days you can restore back.",
      "Actually do a test restore — to a clone, not your real database. Most providers let you spin up a copy from a backup in one click. Do it once before launch so you know how.",
      "Before any production schema migration — adding/dropping columns, renaming tables, changing constraints — take a fresh point-in-time snapshot first. 30 seconds of clicking now beats 6 hours of manually reconstructing data at midnight when the migration eats a column it shouldn't have. Make this a habit, not a launch-day-only thing.",
      "Set yourself a calendar reminder for a weekly manual export (most ORMs and DBs have a one-line dump command), saved somewhere you control (object storage, your laptop). Defense in depth.",
      "Write a one-page note (DISASTER_RECOVERY.md) for future-you: where backups live, exact steps to restore, who to call. Put it next to your code.",
      "NEVER restore directly over your live database without first restoring to a clone and confirming it has what you expected.",
    ],
    redFlags: [
      "You don't actually know whether automatic backups are on for your database",
      "You've never performed a restore — only assumed it would work",
      "You run schema migrations against production without taking a fresh snapshot first",
      "Backups stored in the same account as the database (one compromised login = both gone)",
      "No documented procedure — when disaster strikes, you'll improvise badly",
      "Retention is 24 hours or less (one missed day and you're cooked)",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "The scanner can detect a docs/RECOVER.md (covered by extended internal-audit checks) but cannot confirm the documented procedure has been tested against a real restore. Owner must run the drill once before launch.",
  },
  {
    id: "secure-api",
    number: 11,
    title: "Lock down your app's behind-the-scenes URLs",
    category: "Security",
    priority: "critical",
    timeEstimate: "2 hr+",
    prompt:
      "Act as a backend security engineer. Go through every API endpoint in my app and check four things for each: (1) authentication — is the user logged in? (2) authorization — is THIS user allowed to access THIS specific resource? (the IDOR check); (3) server-side validation — does the backend validate types, ranges, lengths, formats, and required fields before writing or calling paid APIs? (4) safe errors — does the route return generic user-facing errors while logging detailed errors server-side only? Pay especially close attention to endpoints that use IDs from the URL like /users/:id or /orders/:id — these are the most commonly broken. Output a table per endpoint: route, method, requires login? (Y/N), checks resource ownership? (Y/N), validates input server-side? (Y/N), leaks internal error detail? (Y/N), risk level. Then fix every endpoint that's missing checks. Add input validation (Zod, Yup, Valibot, Joi, or my framework's equivalent) to every endpoint — validate types, ranges, lengths, formats, and payload shape on the server, not only in React. Lock down CORS to my own production domain plus localhost/preview as needed — no wildcards in production. After fixes, give me 3 curl commands I can run to verify a logged-out user, a regular logged-in user, and another user's account all get blocked appropriately.",
    what: "Your app has a frontend (what users see) and a backend (the URLs the frontend calls to load and save data — these are called API endpoints). If those backend URLs aren't checking who's asking and what they're allowed to do, anyone with browser developer tools can call them directly and do whatever they want.",
    why: 'This is one of the most common silent disasters in AI-built apps: the frontend hides the "delete account" button from non-admins, but the backend lets anyone call /api/delete-account if they know the URL. The button is decoration; the backend check is the actual lock.',
    steps: [
      'Every endpoint that touches user data should check: "is this person logged in?"',
      "Every endpoint that touches a specific user's data should also check: \"is this person allowed to access THIS user's data?\" This is the most commonly missed step.",
      "Validate every input on the backend — don't trust the frontend to send clean data. Client-side Zod is UX; server-side validation is security.",
      "Return generic errors to users and log detailed errors server-side. Never hand an attacker table names, SQL, stack traces, or schema details.",
      'Ask your AI builder: "go through every API endpoint in my project and tell me which ones don\'t check authentication or authorization, and fix them."',
      "Set up CORS so only your own frontend can call your backend.",
    ],
    redFlags: [
      "Admin functions you can call from a logged-out browser",
      "You can change the user ID in a URL (/api/users/123 → /api/users/124) and read someone else's data",
      "Your backend trusts whatever the frontend sends without re-checking it",
      "Forms only validate in the browser, with no matching server-side schema",
      "API responses expose SQL, table names, stack traces, ORM errors, or internal service URLs",
      "CORS is wide open (Access-Control-Allow-Origin: *) on a non-public API",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found backend endpoints that look like they don't check who's calling or whether the caller owns the data — a route with no auth guard, wide-open CORS, or a pattern where changing an id in the URL could return someone else's records. This is broken object-level authorization, the most common serious flaw in AI-built apps.",
      whyItBlocksLaunch:
        "If any write or admin endpoint is reachable without an auth-and-ownership check, an attacker just changes an id and reads or edits other users' data — no exploit required, only a browser. This is how AI-built apps leak their entire user database, and it's exactly the class of bug builder-native scanners often miss because the endpoint 'works' in normal use.",
      fixInstructions:
        "Make every sensitive endpoint check three things server-side: is the caller authenticated, do they own (or have a role for) the specific resource, and is the input valid. Never trust the frontend. Replace wildcard CORS with an explicit allow-list of your real origins. Return generic errors — never leak SQL, table names, stack traces, or internal URLs. Test by logging in as User B and trying to read User A's records by id.",
      aiBuilderPrompt:
        "Audit every backend endpoint in this project for broken authorization. For each route that returns or changes user data: confirm it checks authentication AND that the caller owns (or has a role for) the specific resource, server-side — not just in the UI. Fix any that change an id in the path/body to reach another user's data. Replace wildcard CORS with an explicit origin allow-list. Make error responses generic (no SQL, stack traces, or internal URLs). Then write me 5 manual tests where User B tries to reach User A's data. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm zero findings under `secure-api`. Then create two test users, log in as User B, and try to read or edit User A's records by changing the id in the URL or request body — confirm every attempt is rejected with a 403/404, not the data.",
    },
  },
  {
    id: "access-control",
    number: 12,
    title: "Decide who's allowed to do what",
    category: "Security",
    priority: "critical",
    timeEstimate: "2 hr+",
    prompt:
      "Act as a senior backend engineer. Help me design and implement a clean role/permission model. First, ask me what user types my app has (e.g., owner, admin, member, free, paid). Then create a single source of truth for permissions — either a permissions matrix or a function like can(user, action, resource) — and wire EVERY sensitive route, mutation, and UI element through it. Default to deny — only allow what's explicitly granted. Hide UI elements based on permissions, but ALSO enforce them server-side (frontend hiding is never a security control). Document the model in a short PERMISSIONS.md so future-me can read it. After you're done, write 5 manual test cases I can run to confirm a regular user can't access admin functionality by URL guessing or modifying request payloads.",
    what: "Most apps have at least two kinds of users — regular users and admins (you). Some have more (free vs. paid, owners vs. members, etc.). Access control is the rules that say “this person can do this, but not that.” Without it, a curious user can stumble into pages or actions they shouldn't have.",
    why: "The classic disaster: a regular user discovers /admin still works for them, deletes a few records to see what happens, and now you have angry users and no backups. Or, more quietly: paid features accidentally available to free users, costing you revenue.",
    steps: [
      "Make a list: what types of users does your app have? (Owner, admin, member, guest, free, paid.)",
      "For each sensitive action (edit, delete, view billing, invite), write down who is allowed.",
      "Enforce those rules on the backend, not just by hiding buttons on the frontend.",
      "Default to no access — only grant what someone explicitly needs.",
      "Try to break it: log in as a regular user and try to access admin URLs directly. Try to access another user's data by changing IDs. If anything works that shouldn't, fix it.",
    ],
    redFlags: [
      "You only enforce permissions by hiding buttons on the frontend",
      "Changing an ID in a URL gives you access to data you shouldn't see",
      "Free users can hit paid features by guessing URLs",
      'There\'s no clear list anywhere of "admin can do X, regular user can do Y"',
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Role-based access boundaries (admin can do X but user cannot) need a runtime test with two real accounts. Code review alone misses bugs in auth-middleware ordering.",
  },
  {
    id: "legal-pages",
    number: 13,
    title: "Add real Terms and Privacy pages (don't fake these)",
    category: "Product & Launch",
    priority: "critical",
    timeEstimate: "1 hr",
    prompt:
      'Act as a product engineer. Add /terms and /privacy pages to my app. IMPORTANT: do not invent legal language. Instead, generate a structured outline of every section that needs to exist in each page, customized to what my app actually does. Detect what to include by inspecting my dependencies and code — list every third-party service I integrate (Stripe, OpenAI, Google Analytics, Resend, Sentry, Supabase, Firebase, Neon, Vercel, Cloudflare, etc.) and note which ones need to be disclosed in the privacy policy. Include a data-location section that points to the separate data-location inventory: where user data lives, what processors touch it, and which deletion/export path covers each one. Output the outline as headings with a 1-sentence description of what each section should cover. Add a clear banner at the top of each page: "This is a starting outline. Get the actual legal language from a lawyer or a service like Termly, iubenda, or Termageddon." Then add the page routes, link them from the footer / signup / cookie banner, and include an "Effective date" field and a real contact email.',
    what: "Two pages most apps need: Terms of Service (the rules of using your app) and a Privacy Policy (what data you collect and what you do with it). They are legal documents — the words matter, and they have to actually describe what your app does.",
    why: "These protect you from getting sued and protect your users from being misled. Most platforms (App Store, Google, Stripe, even Google sign-in) require them. Generated or copy-pasted policies that don't match your actual product are worse than nothing — they're evidence in a lawsuit.",
    steps: [
      "Do not have an AI write your final legal pages. Use a reputable template service (Termly, iubenda, Termageddon) or pay an actual attorney for a few hours.",
      "Tailor whatever template you use to match what your app actually does — every third-party service you use (analytics, AI, payments, database, auth, hosting, email) probably needs to be mentioned.",
      "Create /terms and /privacy pages and link them from the footer, signup, and any place you collect data.",
      "Include an effective date and a real way to contact you.",
      "If you collect cookies or run analytics, add a cookie banner where required (especially in the EU and UK).",
    ],
    redFlags: [
      "No terms or privacy page at all",
      "AI-generated policies that talk about features your app doesn't have",
      "Pages copied from another company (with their company name still in there)",
      "No effective date, no contact info",
      "Your privacy policy doesn't mention services you actually use (Stripe, OpenAI, Google Analytics, etc.)",
      "No one can say which provider or region stores user data",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner couldn't find real Terms of Service and Privacy Policy pages — either the /terms and /privacy routes are missing, or what's there looks like an empty placeholder rather than a policy that describes your actual product and the third-party services it uses.",
      whyItBlocksLaunch:
        "These pages aren't optional. The App Store, Google, Stripe, and even Google sign-in require them, and missing them can block your launch outright. Worse than missing is fake: a generated or copy-pasted policy that names features you don't have — or another company's name — is actively evidence against you in a dispute, not protection.",
      fixInstructions:
        "Add real /terms and /privacy routes and link them from the footer, signup, and anywhere you collect data. Do NOT have an AI write the final legal language — generate a structured outline of the sections each page needs, customized to what your app actually does, then get the real wording from a reputable template service (Termly, iubenda, Termageddon) or an attorney. Inspect your dependencies so the privacy policy names every processor that touches user data (Stripe, OpenAI, Google Analytics, Resend, Sentry, Supabase, etc.). Include an effective date and a real contact email.",
      aiBuilderPrompt:
        "Add /terms and /privacy routes to this app and link them from the footer, signup, and any data-collection surface. Do NOT invent legal language. Instead: (1) inspect my dependencies and code and list every third-party service that receives user data, so I know what the privacy policy must disclose; (2) generate a section-by-section outline for each page, customized to what my app actually does, with a one-line description of what each section should cover; (3) add a visible banner on each page telling me to replace the outline with real language from a lawyer or Termly/iubenda/Termageddon; (4) add an effective-date field and a real contact email. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm `legal-pages` is clean, then load /terms and /privacy in a browser and confirm both render real content, are linked from the footer, and the privacy page names the actual services your code uses.",
    },
  },
  {
    id: "account-deletion",
    number: 14,
    title: "Give users a way to delete their account and export their data",
    category: "Product & Launch",
    priority: "critical",
    timeEstimate: "2 hr+",
    prompt:
      "Act as a privacy-aware product engineer. Add two flows to my app: (1) Account deletion — a button in account settings that, when confirmed (with a second-step modal), permanently deletes the user, all their personal data, and all their content, with a 7-day grace period during which the account can be recovered. After 7 days, the deletion is hard. Email confirmation when initiated and when finalized. (2) Data export — a button that emails the user a downloadable JSON or CSV of all their personal data and content within 24 hours. Audit my schema and tell me which tables/columns count as 'personal data' and need to be included. Make sure the deletion respects foreign-key constraints and removes data from any third party I forward to (Stripe customer, email provider, analytics). Don't break referential integrity for OTHER users (e.g., comments by deleted user become 'deleted user' instead of cascading). Output a short DATA_RIGHTS.md describing what's deleted and what's retained for legal reasons.",
    what: "Two buttons in account settings: 'Download my data' and 'Delete my account.' One emails the user a copy of everything you have on them; the other actually removes them. Both are required almost everywhere personal data is regulated, and both are missing from almost every AI-built app.",
    why: "GDPR (EU), CCPA (California), and an expanding list of US state laws make these legally required if you have any users in those places — which you will, because the internet is global. Beyond legal: it's the right thing, it builds trust, and it costs basically nothing to add now versus a rushed weekend later when someone files a complaint.",
    steps: [
      "Add a 'Delete my account' button in account settings. Require a second confirmation step ('type DELETE to confirm') so it's not accidental.",
      "Implement a 7-day grace period: the account is disabled immediately, deleted permanently after 7 days. Email the user when each happens.",
      "Make sure deletion removes their data from EVERY system: your database, your email provider's contact list, Stripe customer record, analytics, error monitoring. List these in code so future-you remembers.",
      "Add a 'Download my data' button that emails them a JSON or CSV export of everything you have on them within 24 hours.",
      "Write a short page (linked from privacy policy and account settings) explaining what gets deleted, what's kept and why (e.g., financial records you must legally retain), and how long it all takes.",
    ],
    redFlags: [
      "No way for a user to delete their account from inside the app",
      "Deleting an account leaves their data in your database 'just in case'",
      "Deleting an account removes them from your DB but not from Stripe / your email tool / your analytics",
      "No way for a user to get a copy of their data",
      "You'd genuinely struggle to comply if a user emailed you tomorrow asking to be deleted",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "A delete-account endpoint can exist in code without working end-to-end (cascade handling, third-party deletions, grace period, confirmation flow). Run the flow with a test account and confirm every related row is gone.",
  },
  {
    id: "consent-banner",
    number: 15,
    title: "Add a cookie / consent banner if you have any non-US traffic",
    category: "Product & Launch",
    priority: "critical",
    timeEstimate: "1 hr",
    prompt:
      "Act as a privacy-compliance engineer. Add a GDPR/CCPA-compliant consent banner to my app. Requirements: (1) shows on first visit; (2) clearly distinguishes 'strictly necessary' cookies (always on, no consent needed) from 'analytics/marketing/advertising' (off by default — explicit opt-in); (3) BEFORE consent, no analytics, no third-party trackers, no advertising pixels load — only essential auth/session cookies; (4) AFTER consent, the chosen categories load. Use a reputable open-source library (CookieConsent, Klaro) or a service (Cookiebot, Termly's banner). Inventory every cookie and tracker my app currently sets — list them in the banner UI by category. Give users a persistent way to change their choice later (footer link). Don't fake the 'reject all' button — it has to actually do nothing. Document each cookie in the privacy policy.",
    what: "A small banner that asks visitors before you load analytics, ad pixels, or any non-essential tracking. Required by law in the EU and UK (GDPR/ePrivacy), and increasingly in California, Brazil, Canada, and a growing list of US states. Even if your business is US-only, the moment one person from London visits your site, you're inside their rules.",
    why: "Missing or fake consent banners carry real fines. Cookie and tracking violations are usually enforced under national ePrivacy laws, which have their own (often lower) caps — the headline GDPR maximum of €20M or 4% of annual worldwide turnover is the ceiling for the worst data-protection breaches, not a flat penalty for a missing banner. Enforcement against small sites has ramped up either way. Beyond fines, ad networks and analytics tools (Google in particular) increasingly require valid consent signals before they'll work, and a growing list of US state laws — Indiana, Kentucky, and Rhode Island all took effect January 2026, with Rhode Island's threshold as low as ~35,000 consumers and no cure period — expect you to honor opt-outs and Global Privacy Control browser signals.",
    steps: [
      "Use a battle-tested library: CookieConsent (open-source, free), Klaro, or a service like Cookiebot or Termly. Don't build this from scratch.",
      "Inventory every cookie and tracker your app sets. Group into 'Strictly necessary' (auth, session — always on) and 'Analytics & marketing' (off by default).",
      "Block analytics scripts, ad pixels, and any third-party tracker from loading until the user opts in. Most consent libraries handle this if wired correctly.",
      "Make 'Reject all' a single click and equally prominent as 'Accept all.' Dark patterns ('Accept all' is a big button, 'Reject' is hidden) are themselves illegal.",
      "Add a persistent way to change consent later — usually a footer link like 'Cookie preferences.'",
    ],
    redFlags: [
      "No consent banner at all and you have non-US users",
      "Analytics or ad pixels load before the user has accepted",
      "'Reject all' button is hidden, missing, or styled to look unclickable",
      "Banner has only an 'OK' button — that's not consent, that's notice",
      "You can't list every cookie your site sets and what each one does",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Whether a consent banner is required depends on what tracking cookies the live app sets and which jurisdictions you serve. Runtime + legal call, not a code property.",
  },
  {
    id: "payments",
    number: 16,
    title: "Make sure payments actually work before you charge people",
    category: "Product & Launch",
    priority: "critical",
    timeEstimate: "2 hr+",
    prompt:
      "Act as a payments engineer. Audit my app's entire paid flow before launch. First, identify whether I use Stripe, Lemon Squeezy, Paddle, RevenueCat, app-store payments, or something else. Then verify and fix: (1) checkout can be created only by the server, never with a client-supplied price or product; (2) the success page does NOT unlock paid access just because the URL says success; it checks the backend for a paid order; (3) webhooks verify the provider signature and persist paid status, receipt ID, amount, currency, and customer email; (4) every paid product, subscription, upgrade, cancellation, refund, and failed-payment state has a real user-facing path; (5) test-mode checkout, webhook delivery, receipt email, refund, and cancellation all work end-to-end. Output exact test-card steps, webhook setup steps, env vars, and the one thing I should click in the provider dashboard to prove money would actually move.",
    what: "If your app charges money, the payment flow is not 'done' when the checkout button opens. It is done when payment succeeds, your backend hears the signed webhook, paid access unlocks, the receipt lands, and cancellation/refund paths do not strand the user.",
    why: "This is where AI-built apps embarrass themselves fast. A team launches, someone pays, the success page lies, the webhook never arrives, and now the first customer is both confused and charged. Or worse: a user edits a client-side price and buys the expensive thing for $0. Payments need a real dry run before launch day.",
    steps: [
      "Run a full test-mode checkout from a logged-out or brand-new account. Pay with the provider's test card and confirm the success page shows the right purchased thing.",
      "Verify paid access comes from your backend's recorded payment state, not from a success URL, localStorage flag, or client-side boolean.",
      "Open the provider dashboard and confirm the webhook endpoint is live, signing is verified in code, and the event was delivered successfully.",
      "Test the unhappy paths: failed card, duplicate click, refresh after checkout, refund, cancellation, expired subscription, and trying to access paid content before the webhook arrives.",
      "Send yourself the receipt or confirmation email and confirm it lands in the inbox with the right amount, product, support contact, and refund/cancel instructions.",
    ],
    redFlags: [
      "The frontend sends the price, plan, or product ID and the backend trusts it",
      "Paid access unlocks just because the browser landed on /success",
      "No webhook handler, or a webhook handler that does not verify provider signatures",
      "You have never tested refund, cancellation, failed card, or duplicate checkout",
      "A customer could pay and have no obvious way to get help if access does not unlock",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found a payment integration (Stripe or similar) where the webhook handler or the post-checkout verification looks missing, unverified, or incomplete. That usually means your app is deciding whether someone paid based on the browser redirect alone, instead of a signed server-to-server confirmation.",
      whyItBlocksLaunch:
        "If you unlock access from the client redirect instead of a verified webhook, two things break: a user who closes the tab after paying may never get what they bought (a refund and a bad review), and a user who fakes the redirect can unlock without paying. Charging real money on top of an unverified flow is the kind of bug that erodes trust the moment it happens to someone.",
      fixInstructions:
        "Verify payment server-side. Handle the provider's webhook (e.g. checkout.session.completed), and validate its signature with the official SDK against the raw request body — mount the webhook route before any JSON body parser. Persist the paid state and unlock access from that verified event, not the redirect. Then walk the whole flow: successful checkout, closed-tab-after-pay, failed card, duplicate checkout, and refund/cancellation.",
      aiBuilderPrompt:
        "Audit my payment integration. Confirm there's a server-side webhook handler (e.g. /api/webhooks/stripe) that verifies the provider's signature against the raw body (mounted before any JSON parser) and unlocks access from the verified event — not from the browser redirect. If access is granted client-side, move it to the webhook. Persist paidAt and the customer id. Then give me a test plan covering successful pay, closed-tab-after-pay, failed card, duplicate checkout, and refund. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm zero findings under `payments`. Then run a real test-mode checkout, close the tab immediately after paying, and confirm the purchase still unlocks (proving the webhook, not the redirect, granted access). Trigger a refund and confirm the app handles it.",
    },
  },
  {
    id: "file-uploads",
    number: 17,
    title: "Lock down uploads and private files",
    category: "Security",
    priority: "critical",
    timeEstimate: "2 hr+",
    prompt:
      "Act as an application security engineer. Audit every place my app accepts, stores, processes, previews, or downloads user files. For each upload path, verify and fix: (1) max file size and per-user storage quota; (2) MIME/type allowlist checked on the server, not only by file extension; (3) dangerous files rejected or sandboxed (HTML, SVG with scripts, executables, archives if not needed); (4) filenames normalized so path traversal like ../ cannot work; (5) private files stored outside the public web root or in object storage with private buckets and signed, expiring URLs; (6) image/document processing strips metadata where appropriate and cannot execute embedded code; (7) antivirus or malware scanning is added if users can share files with others. Output every upload route, who can access each file afterward, and exact manual tests I should run before launch.",
    what: "Uploads are any file a user can give your app: avatars, PDFs, CSVs, images, documents, audio, exports, attachments. They look harmless until one private upload becomes public, one huge file knocks over your server, or one malicious file gets served back to another user.",
    why: "AI builders love to wire 'upload a file' in one prompt and skip the boring safety rails. That means public buckets, unlimited file sizes, trusting .jpg extensions, and download URLs anyone can guess. If users trust you with files, you need to prove those files stay private and bounded.",
    steps: [
      "List every upload entry point: avatar, import, support attachment, chat file, document, CSV, admin upload, anything.",
      "Set hard limits: allowed file types, max file size, per-user storage quota, and max number of files per object or account.",
      "Validate type on the server using MIME sniffing or file magic, not just the browser's accept attribute or the filename extension.",
      "Store private files in a private bucket and serve them through signed, short-lived URLs after checking the current user is allowed to read that exact file.",
      "Try to break it: upload a huge file, a renamed .exe, an HTML file, an SVG with script, a filename with ../, and another user's file URL. All should fail safely.",
    ],
    redFlags: [
      "Uploads go directly into a public /uploads folder or public object-storage bucket",
      "Only the frontend checks allowed file types",
      "No max file size or storage quota",
      "Anyone with the URL can view another user's supposedly private file",
      "Uploaded SVG/HTML files are served back as executable browser content",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found file-upload handling that looks unsafe — no server-side type/size limit, files stored somewhere publicly listable, or user-controlled filenames that could escape their folder. Uploads are one of the easiest ways for a small app to get attacked because the user hands you a file and you run or serve it.",
      whyItBlocksLaunch:
        "An unguarded upload lets an attacker fill your storage, upload an executable disguised as an image, or serve an HTML/SVG file back to other users as active content (stored XSS). If private files sit in a publicly listable bucket, anyone with a URL — or who can guess one — reads another user's documents. These are real, common breaches for AI-built apps.",
      fixInstructions:
        "Validate every upload server-side: allow-list the MIME types and extensions you actually accept, cap the file size, and generate your own safe, random filenames (never trust the client's). Store uploads in private object storage with public listing off, and serve them through short-lived signed URLs — not a public path. Never serve uploaded SVG/HTML as active content; force a safe content-type or download disposition.",
      aiBuilderPrompt:
        "Harden every file-upload path in this project. Enforce server-side: a MIME + extension allow-list, a maximum file size, and app-generated random filenames (ignore the client filename to prevent path traversal). Move uploads to private storage with directory listing disabled and serve them via short-lived signed URLs instead of public paths. Make sure uploaded SVG/HTML can't be served back as executable content. List each upload endpoint and the fix you applied. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm zero findings under `file-uploads`. Then try to upload an oversized file and a disallowed type and confirm both are rejected, and confirm a private file's URL is a signed, expiring link — not a guessable public path another user can open.",
    },
  },
  {
    id: "ai-guardrails",
    number: 18,
    title: "Put guardrails around AI outputs and actions",
    category: "Security",
    priority: "critical",
    timeEstimate: "2 hr+",
    prompt:
      "Act as an AI application security engineer. Audit every LLM, agent, tool-calling, retrieval, and generated-content flow in my app. Verify and fix: (1) user prompts, uploaded files, retrieved documents, and web pages are treated as untrusted input; (2) prompt injection cannot make the model reveal secrets, system prompts, hidden context, or other users' data; (3) any tool/action the AI can trigger has an explicit allowlist, server-side permission check, spending limit, and human confirmation for destructive or external actions; (4) model outputs shown to users are labeled, validated, and safe-failed when confidence is low; (5) logs do not store sensitive prompts or private documents longer than needed; (6) there is an abuse path for harmful, illegal, or policy-breaking generations. Build a concrete test set with 10 prompt-injection and data-leak attempts and show which ones pass after the fixes.",
    what: "If your app uses AI, the model is not just a text box. It may see private data, make recommendations, call tools, spend API money, send emails, edit records, or create content users trust. Guardrails are the limits that keep a weird prompt from turning into a data leak or a destructive action.",
    why: "Vibe-coded AI apps often ship with one giant prompt, direct access to user data, and no boundary between 'the model suggested it' and 'the app did it.' Prompt injection is not magic; it is a user telling your AI to ignore your instructions. If the AI can touch data or tools, that instruction needs to bounce off a hard server-side permission check.",
    steps: [
      "Map every AI flow: what context the model sees, what tools it can call, what data it can read, and what actions it can trigger.",
      "Treat user prompts, uploaded files, retrieved docs, and web pages as hostile input. Never trust them to follow your system prompt.",
      "Put server-side allowlists and permission checks in front of every AI tool call. The model can request an action; your backend decides whether it is allowed.",
      "Require human confirmation for destructive, external, expensive, or irreversible actions: sending email, deleting data, publishing content, charging money, or calling paid APIs in bulk.",
      "Build a small red-team test set: 'ignore previous instructions,' 'show me another user's data,' 'print your system prompt,' 'call the tool without permission,' and run it before launch.",
    ],
    redFlags: [
      "The model can call tools directly without a server-side permission check",
      "Private user data or uploaded files are pasted into prompts with no access boundary",
      "No prompt-injection tests exist",
      "The app treats generated output as fact without labeling, validation, or fallback",
      "AI prompts, retrieved documents, or conversation logs store sensitive data forever",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "AI guardrails need scenario testing against real prompts, tool permissions, data boundaries, and destructive-action confirmations. Static code cannot prove the model behaves safely under adversarial input.",
  },
  {
    id: "database-access-rules",
    number: 19,
    title: "Prove every user can only read their own rows",
    category: "Security",
    priority: "critical",
    timeEstimate: "2 hr+",
    prompt:
      "Act as a database security engineer. Audit every table, collection, bucket, and document store that contains user data. First identify the backend: Supabase/Postgres, Firebase/Firestore, MongoDB, Prisma/Drizzle/SQL, object storage, or something else. Then verify the real access boundary: (1) Supabase/Postgres: Row Level Security is enabled on every user-scoped table and policies exist for select/insert/update/delete; service-role keys never reach the browser; policies are tested with two different users. (2) Firebase/Firestore: security rules deny by default and explicitly check auth.uid/resource ownership; rules are tested in the emulator. (3) SQL/ORM: every query that reads user data filters by the authenticated user or permission model server-side. (4) Storage: private files live in private buckets with signed URLs and ownership checks. Output a table: data surface, user-scoped? rule/policy present? cross-user test passed? risk. Then write the exact SQL/rules/tests needed to close gaps.",
    what: "Database access rules are the lock underneath your UI. Your frontend can hide another user's records, but the database or API still has to refuse the request when someone changes an ID, opens DevTools, or calls the endpoint directly.",
    why: "This is the classic AI-built app data breach: the app looks private, but Supabase RLS is off, Firebase rules allow broad reads, or the server query forgets `where user_id = currentUser.id`. That is not a hack; it is an unlocked door.",
    steps: [
      "List every user-scoped table, collection, storage bucket, and API route that returns saved user data.",
      "For Supabase, enable RLS on every user-scoped table and write policies for select, insert, update, and delete. Do not ship with zero policies.",
      "For Firebase/Firestore, make rules deny by default and allow reads/writes only when auth.uid owns the document or has an explicit role.",
      "Test with two real test users: create data as User A, log in as User B, and try to read, edit, or delete User A's records through the app, the API, and any SDK/browser console path.",
      "Do the highest-yield check the breaches all share: with ONLY your public anon/publishable key (no login), query every user table directly — bypass your own UI. Open a console, point the Supabase/Firebase client at your project with just the public key, and try to select rows. If any row comes back, RLS is off or mis-scoped. This is the exact gap that leaked millions of records from AI-built apps; a builder's own scanner may confirm RLS 'exists' without proving it scopes rows correctly.",
      "Keep privileged service-role/secret/admin keys server-side only. If a browser bundle can use the key to bypass rules, the rules do not matter — and note Supabase's newer key names (publishable = browser-safe, secret = server-only) alongside the legacy anon/service_role terms.",
    ],
    redFlags: [
      "Supabase table shows RLS disabled or zero policies",
      "Firestore rules include broad allow read/write statements",
      "The frontend hides records but backend/API queries do not check ownership",
      "Service-role/admin/database credentials are present in browser code",
      "No cross-user test has ever been run with two separate accounts",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Database access rules must be proven against the real provider and two real users. Static code can spot hints, but it cannot prove Supabase RLS, Firebase rules, storage policies, and cross-user ownership tests all work in the deployed environment.",
  },
  {
    id: "auth-failure-cases",
    number: 20,
    title: "Test the auth failures attackers try first",
    category: "Security",
    priority: "critical",
    timeEstimate: "30 min",
    prompt:
      "Act as a QA/security engineer. Run the auth failure-case drill before launch, using production-similar auth settings and throwaway test accounts. Test: (1) wrong password or wrong OTP 5-6 times in a row — confirm rate limiting/lockout and generic copy; (2) password reset or magic-link start for an email that does not exist — confirm it looks the same as a real email path and does not reveal account existence; (3) verification or magic link clicked twice, opened after expiry, and opened on a different device — confirm it lands in a safe state with a recovery path; (4) signup with an already registered email or phone — confirm it does not leak account state beyond the provider's safe default; (5) login from mobile and desktop — confirm session/cookie behavior is correct. Output pass/fail evidence, screenshots or curl commands where useful, and the exact copy users see.",
    what: "Happy-path auth testing proves almost nothing. The dangerous bugs are in the weird edges: wrong codes, fake emails, repeated attempts, duplicate signup, expired links, and users opening links on a different device.",
    why: "Attackers probe the failure paths first because they reveal whether an account exists, whether a code can be brute-forced, and whether a user can get locked out. Paid users hit the same paths accidentally on launch day.",
    steps: [
      "Try the wrong password, magic code, or OTP 5-6 times. Confirm a real limit kicks in and the message stays generic.",
      "Start password reset or magic-link login for an email that does not exist. The response should look like success, not 'account not found.'",
      "Click the same verification/magic link twice and after expiry. It should recover gracefully, not show a stack trace or reveal internals.",
      "Sign up with an email or phone that already exists. Confirm the provider's safe default copy and rate limits are used.",
      "Record the exact pass/fail evidence in the launch report so nobody hand-waves auth as 'probably fine.'",
    ],
    redFlags: [
      "Wrong password or OTP can be tried indefinitely",
      "Password reset says whether an email exists",
      "Verification links crash or leak internals when reused",
      "Signup copy reveals registered users in a way attackers can enumerate",
      "No one has tested auth failure states outside the happy path",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Auth failure behavior requires a live auth provider, delivered emails/SMS, real browser sessions, and throwaway accounts. The scanner can flag code signals, but it cannot honestly click links, trigger provider lockouts, or verify copy in every failure state.",
  },
  {
    id: "data-location-inventory",
    number: 21,
    title: "Know where every piece of user data lives",
    category: "Product & Launch",
    priority: "critical",
    timeEstimate: "1 hr",
    prompt:
      "Act as a privacy and infrastructure operator. Build a data-location inventory for this app before launch. Inspect the code, dependencies, env var names, docs, provider dashboards, and signup/payment/email/auth flows. Output a table with: data type collected, source form/route, primary store, provider, region/location if available, third parties that receive it, retention period, deletion/export path, and policy disclosure needed. Include email providers, auth providers, analytics, error monitoring, payment processors, AI providers, file storage, databases, logs, and support tools. If a provider dashboard is needed to confirm region, say exactly which dashboard page must be checked. Do not invent regions — mark unknown until verified.",
    what: "The moment you collect an email, payment, file, prompt, or user profile, you need to know where it goes. 'It is somewhere in Supabase' or 'Vercel handles it' is not enough when a user asks for deletion or a platform asks for your privacy details.",
    why: "Legal pages only protect you if they match reality. If your app sends user data to Stripe, OpenAI, Resend, Sentry, PostHog, Supabase, Firebase, Neon, or a support inbox, those processors and regions have to be known before launch.",
    steps: [
      "List every data collection point: signup, checkout, waitlist, contact form, uploaded file, AI prompt, analytics event, error log, support request.",
      "For each one, write where it is stored first, which third parties receive it, and how long it is kept.",
      "Open provider dashboards and record region/location where available: database, hosting, auth, email, analytics, AI, payments, storage, logs.",
      "Tie every data store to a deletion/export path so account deletion is not just deleting one database row.",
      "Update the privacy policy outline so it names the real categories of data, processors, retention, and deletion/export contact.",
    ],
    redFlags: [
      'You cannot answer "where does a new user email go?"',
      "Privacy policy names fewer processors than the code actually uses",
      "No one knows the database/auth/storage region",
      "Error monitoring or analytics receives personal data without disclosure",
      "Account deletion only touches the app database and ignores Stripe, email, analytics, logs, or support tools",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Data location depends on live provider dashboard settings, regions, processors, and retention choices. Static repo scanning can infer likely services, but it cannot prove where provider-held data physically lives or whether privacy disclosures match reality.",
  },
  {
    id: "public-form-abuse",
    number: 22,
    title: "Block bots from public forms before launch",
    category: "Security",
    priority: "critical",
    timeEstimate: "1 hr",
    prompt:
      "Act as an abuse-prevention engineer. Find every public form or unauthenticated write surface: signup, login/OTP send, password reset, waitlist, contact, feedback, newsletter, invite request, file upload, AI demo, support, and checkout-start. For each one, decide whether it needs CAPTCHA/Turnstile, rate limiting, email/phone verification, honeypot fields, server-side validation, or all of the above. Prefer Cloudflare Turnstile for public marketing/contact/waitlist forms because it is free and privacy-friendly. Add the provider secret server-side only, verify tokens on the backend before accepting the submission, keep localhost/dev bypasses development-only, and add abuse logging. Then test with a missing token, invalid token, repeated submissions, and a real browser pass.",
    what: "Public forms are doors bots can walk through without an account. If they can submit freely, they will fill your waitlist with spam, burn SMS/email credits, scrape paid APIs, or bury real leads under junk.",
    why: "A polished launch can still get wrecked by a public form with no bot guard. The app looks fine until the first traffic spike turns into 500 spam contacts, SMS pumping, or an AI endpoint bill.",
    steps: [
      "Inventory every unauthenticated form or POST route, not just the contact form.",
      "Put CAPTCHA or Cloudflare Turnstile on public marketing/contact/waitlist/feedback forms that accept arbitrary submissions.",
      "Keep rate limits on every public write endpoint even when CAPTCHA is present. CAPTCHA slows bots; rate limits cap damage.",
      "Verify bot tokens server-side before writing to the database, sending email/SMS, or calling a paid API.",
      "Test missing-token, invalid-token, repeated-submit, and real-browser success paths before launch.",
    ],
    redFlags: [
      "Contact, waitlist, feedback, signup, or OTP forms accept unlimited public submissions",
      "CAPTCHA token is checked only in the frontend",
      "CAPTCHA is present but the endpoint still writes data when the token is missing",
      "No rate limit backs up the CAPTCHA",
      "Development/test bypass can run in production",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Bot protection has to be verified against live public forms and provider token validation. The scanner can look for rate-limit or CAPTCHA libraries, but it cannot prove every unauthenticated form rejects missing tokens and survives repeated submissions.",
  },
  {
    id: "model-freshness",
    // number assigned by the index.ts assembly (position-based)
    number: 0,
    title: "Verify every AI model ID your app calls still exists",
    category: "Operations",
    priority: "critical",
    timeEstimate: "30 min",
    prompt:
      "Act as a release engineer. Find every AI model ID my app calls and make sure none of them are retired or about to be. (1) Grep the whole codebase for hardcoded model strings — gpt-*, o1/o3/o4-*, claude-*, gemini-*, text-embedding-*, and any provider SDK call that passes a `model` argument. (2) For each one, check it against the provider's current deprecation page (OpenAI, Anthropic, Google) and tell me which are already retired, which have a shutdown date, and which are fine. (3) Replace every dated snapshot (e.g. a model ending in -2024-05-13 or -0613) and every literal model string with a single value read from config or an environment variable, so I can change the model in one place. (4) Add a tiny pre-launch smoke test that actually calls each provider with its configured model and fails loudly if the model no longer exists. Show me the diff before applying, then give me the shutdown dates to put on my calendar.",
    what: "AI providers retire old models on a schedule. When they do, any call to that model ID stops working and returns an error — so an app that hardcoded a model name silently breaks the moment the shutdown date passes, usually with no warning to you.",
    why: "This is a brand-new way for AI-built apps to die, and it's on a clock. Across 2026, OpenAI, Anthropic, and Google all retired waves of model IDs (OpenAI has hard shutdown dates on July 23 and October 23; Anthropic retires Claude Opus 4.1 on August 5; Google's Gemini 2.0 is already gone and 2.5 is dated for October 16). If your AI feature points at a dead model, it doesn't degrade gracefully — it just starts throwing errors for every user until you notice and fix it. AI builders love to hardcode a specific dated model; that's the trap.",
    steps: [
      "Search your code for every model ID: gpt-, o1/o3/o4-, claude-, gemini-, text-embedding-, and anything passed as a `model` argument to a provider SDK.",
      "Check each against the provider's deprecation page (platform.openai.com/docs/deprecations, docs.claude.com model deprecations, ai.google.dev deprecations). Note which are retired, which have a shutdown date, and which are current.",
      "Stop pinning dated snapshots (anything ending in a date like -2024-05-13 or -0613). Point at the current stable model instead.",
      "Move the model name into config or an env var so you can change it in one place without a code hunt.",
      "Add a pre-launch smoke test that calls each provider with its real configured model and fails if the model is gone.",
      "Put the known shutdown dates (July 23, August 5, October 16, October 23, 2026) on your calendar so a future retirement doesn't surprise you.",
    ],
    redFlags: [
      "A dated model snapshot hardcoded in source (ends in a date or a 4-digit code)",
      "The same model string copy-pasted across many files instead of read from one config value",
      "You can't say, off the top of your head, which model your app is calling",
      "No smoke test confirms the model is live before you ship",
      "Your AI feature has no fallback or error handling when a model call fails",
    ],
    references: [
      {
        label: "OpenAI model deprecations",
        url: "https://platform.openai.com/docs/deprecations",
      },
      {
        label: "Anthropic model deprecations",
        url: "https://docs.claude.com/en/docs/about-claude/model-deprecations",
      },
      {
        label: "Google Gemini deprecations",
        url: "https://ai.google.dev/gemini-api/docs/deprecations",
      },
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found a hardcoded AI model ID in your code that is either already retired or scheduled for shutdown by its provider, or is pinned to a dated snapshot that will be retired on a schedule. Right now your app is calling a model name as a literal string instead of reading it from config.",
      whyItBlocksLaunch:
        "When a provider retires a model, every call to that ID returns an error — the AI feature doesn't degrade, it just breaks for every user until you notice. OpenAI, Anthropic, and Google all retired waves of models across 2026 with hard shutdown dates, so a pinned model is a launch that quietly stops working on a date you didn't write down.",
      fixInstructions:
        "Replace the hardcoded model string with a value read from config or an environment variable, so the model lives in exactly one place. Swap any dated snapshot for the current stable model. Add a small pre-launch smoke test that calls the provider with the configured model and fails if it no longer exists. Then check the provider's deprecation page and calendar the shutdown dates for whatever you're on.",
      aiBuilderPrompt:
        "Find every hardcoded AI model ID in this project (gpt-*, o1/o3/o4-*, claude-*, gemini-*, text-embedding-*, and any `model` argument to a provider SDK). For each, tell me the file, the line, and whether it is retired, scheduled for shutdown, or current per the provider's deprecation page. Move every model name into a single config/env value, replace dated snapshots with the current stable model, and add a pre-launch smoke test that calls each provider with its configured model and fails if the model is gone. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm zero findings under `model-freshness`. Then run your smoke test (or make one real call per provider) and confirm each configured model responds instead of returning a 'model not found' error.",
    },
  },
  {
    id: "ai-disclosure",
    number: 0,
    title: "Tell users they're talking to AI (and label AI-generated content)",
    category: "Operations",
    priority: "critical",
    timeEstimate: "1 hr",
    prompt:
      "Act as a product engineer who understands AI transparency law. If my app has any user-facing AI feature — a chatbot, an assistant, or anything that generates text, images, audio, or video — make it compliant. (1) Add a clear, visible 'you're chatting with AI' disclosure at the start of any AI conversation and whenever a user directly asks — in the UI, not buried in the Terms. (2) If my app generates media, add machine-readable provenance/marking (e.g. C2PA metadata or a visible label) so AI-generated content is detectable. (3) If my app is consumer-facing and minors can reach the AI, add a self-harm/crisis response path and content filters. (4) Tell me plainly which of these apply to me based on where my users are (EU / California / elsewhere) and what my AI feature does. Don't over-build — show me the smallest compliant version first, then let me decide.",
    what: "New transparency laws require apps to tell people when they're interacting with AI, and to label AI-generated content. If your app has a chatbot or generates media, you now have specific disclosure duties — and for consumer chatbots, extra duties around self-harm and protecting minors.",
    why: "This became enforceable in 2026, not someday. The EU AI Act's transparency rules (Article 50) apply from August 2, 2026 to any app with an AI feature that EU users can reach: chatbots must disclose they're AI, and generated media must be machine-readable marked. California's companion-chatbot law (SB 243) took effect January 1, 2026 with disclosure, self-harm-response, and minor-protection duties and per-violation penalties. A hidden disclosure in your Terms doesn't count — it has to be visible where the user actually is.",
    steps: [
      "Decide if this applies: do you have a chatbot, AI assistant, or content generator that EU or California users can reach? If yes, keep going.",
      "Add a visible 'you're interacting with AI' disclosure at the start of the AI experience and whenever a user asks — in the interface, not only in the Terms.",
      "If you generate images, audio, or video, add machine-readable provenance (C2PA) or a clear visible label so the output is detectable as AI-generated.",
      "If your chatbot is consumer-facing and minors can use it, add a self-harm/crisis response path and age-appropriate content filters.",
      "Keep a short record of what you did — substantiating your compliance is cheap now and expensive later.",
    ],
    redFlags: [
      "An AI chatbot with no 'this is AI' disclosure anywhere the user can see it",
      "AI-generated images or video shipped with no label or provenance metadata",
      "The only 'disclosure' is a line buried in your Terms of Service",
      "A consumer chatbot minors can reach with no crisis-response or content filtering",
      "You can't say whether EU or California users can access your AI feature",
    ],
    references: [
      {
        label: "EU AI Act Article 50",
        url: "https://artificialintelligenceact.eu/article/50/",
      },
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Whether a disclosure is visible, well-placed, and legally sufficient — and whether your users are in a jurisdiction that requires it — is a product and legal judgment. The scanner can't see your live chat UI or know where your users are.",
  },
];
