import type { ChecklistItem } from "./types.js";

export const ITEMS_CRITICAL_A: ChecklistItem[] = [
  {
    id: "value-prop",
    number: 1,
    title: "Be able to explain what this is in one sentence",
    category: "Product & Launch",
    priority: "critical",
    timeEstimate: "1 hr",
    prompt:
      "Act as a sharp positioning consultant in the style of April Dunford. I'll describe my product to you. Push back if my answers are vague — keep asking until you have specifics. Then craft a one-sentence value proposition using this template: \"[App] helps [specific person] [do specific thing] without [common pain].\" Give me 3 alternative versions varying tone (confident, plain, slightly playful). Then write 3 supporting bullets that are outcomes, not features. Finally, draft a 60-word elevator pitch I could say out loud at a party. Before writing anything, ask me: who exactly is the target user, what do they currently use instead, and why does that current solution suck for them. Don't generate a single line of marketing copy until you have those three answers.",
    what: "If a stranger lands on your homepage and can't figure out what you do in five seconds, they're gone. Same if you can't answer “so what does it do?” at a party without rambling. The exercise of squeezing your app into one clear sentence forces you to find the actual point.",
    why: "Most launches don't fail from bad code — they fail because nobody understands why they should care. A clear one-line pitch is what makes someone read the second sentence.",
    steps: [
      'Fill in the template: "[App] helps [specific person] [do specific thing] without [common pain]." Specific beats clever every time.',
      "Put that sentence at the very top of your homepage in big, confident text.",
      "Add three short supporting bullets that prove it (not adjectives — actual outcomes).",
      'Identify exactly who it\'s for. "Everyone" is not a target.',
      "Read your sentence to 5 people who don't know your app. If they can't roughly repeat it back, it's not done.",
    ],
    redFlags: [
      'Generic descriptions like "the best [thing] for [vague]"',
      "You can't name a specific person it's for",
      "Friends still don't get it after you explain twice",
      "Your homepage talks about features instead of what changes for the user",
      "You can't say what makes you different from the obvious alternative",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "A clear one-sentence value prop is a positioning judgment, not a code property. The scanner can detect a homepage exists; only a human can decide whether the sentence on it actually lands with target users.",
  },
  {
    id: "ai-audit",
    number: 2,
    title: "Audit what your AI builder actually shipped",
    category: "Operations",
    priority: "critical",
    timeEstimate: "2 hr+",
    prompt:
      "Act as a senior engineer doing a code audit on a project I built mostly with AI. Walk through every file and flag anything that looks like leftover scaffolding, mock data, or unfinished work that snuck into a real user flow. Specifically search for and list, with file and line: TODO/FIXME/XXX/HACK comments; the strings 'mock', 'dummy', 'placeholder', 'lorem', 'fake', 'sample', 'stub'; hardcoded test emails (test@example.com, john.doe, jane.doe); hardcoded fake names, fake numbers, fake credit cards; functions that return the same constant regardless of input; console.log/print statements anywhere on a real request path; debug routes, /test pages, or admin shortcuts. For each finding tell me: is this real work that needs to be done, or leftover scaffolding to delete. Then pick 3 of my most important functions and walk me through line by line what they actually do, in plain English, so I can tell if they match what I think they do. Don't fix anything yet — give me the report first.",
    what: "Your AI builder is a fast, productive contractor who occasionally lies. It will tell you 'done!' when something is actually mocked, stubbed, hardcoded, or half-built. Before you launch you need to do a literal walkthrough of your codebase looking for the patterns AI builders ship by accident.",
    why: "Vibe-coded apps go live with placeholder users called 'John Doe', mock API responses returning the same fake data every time, TODO comments inside real flows, debug logs leaking sensitive info, and functions that return constants instead of doing the thing. None of that explodes loudly — it just quietly makes your app a lie until a real user notices.",
    steps: [
      "In your editor, do a project-wide search (Cmd+Shift+F or your platform's search) one string at a time: TODO, FIXME, XXX, HACK, mock, dummy, placeholder, lorem, fake, sample, stub.",
      "For each hit, decide: real work to finish, or leftover scaffolding to delete.",
      "Search for hardcoded test data: test@example.com, john.doe, jane.doe, 555-1234, password123. Anything that smells synthetic shouldn't be in production code.",
      "Open an incognito window and use your app as a brand new user. Sign up. Do the main thing. Does data actually save somewhere real, or are you looking at the same fake response every time?",
      "Pick 3 random functions and ask your AI builder: 'walk me through what this does line by line in plain English.' If the explanation is fuzzy or doesn't match what you thought it does, that's a bug waiting.",
    ],
    redFlags: [
      "console.log or print statements on production code paths (especially logging tokens, full user records, or request bodies)",
      "Functions that return the same value every time regardless of input",
      "Forms that show a success message but you can't find the saved data anywhere",
      "Comments like 'TODO: implement this' or 'replace with real API'",
      "Variable names like fakeUsers, mockData, or testItems being used in production paths",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found content that looks like leftover scaffolding from your AI builder — TODO/FIXME/HACK comments, placeholder strings ('lorem ipsum', 'John Doe', 'test@example.com'), or console-style debug calls sitting on real code paths. These are the patterns AI builders ship by accident: a contractor that says 'done' when the work is actually mocked or unfinished.",
      whyItBlocksLaunch:
        "Vibe-coded apps go live with placeholder users called 'John Doe', mock API responses returning the same fake data every time, and debug log calls leaking tokens to the server log. None of that explodes loudly — it just quietly makes your app a lie until a real user notices and screenshots it.",
      fixInstructions:
        "Treat each flagged file as a decision point: is this real work that needs to be finished, or leftover scaffolding to delete? Replace mock data with real database calls. Remove debug log statements from production paths. Either implement the TODO or remove the comment. Re-run the scanner — every finding should either be gone or downgraded with a documented reason.",
      aiBuilderPrompt:
        "Walk through every finding in this scan flagged under 'ai-audit'. For each one, tell me: is this real work that needs to be done, or leftover scaffolding to delete? For TODO/FIXME comments, propose what the code should actually do (don't just remove the comment if there's missing logic). For placeholder strings like 'lorem ipsum' or 'test@example.com', replace with real content or remove the surface. For debug log statements on request paths, remove them but propose proper structured logging if the trace was actually useful (use the project's logger, never raw console output on a request path).",
      verificationStep:
        "Re-run `npx shippingszn` and confirm zero findings tagged `ai-audit`. Then open the app in an incognito window and use it as a brand-new user — confirm data persists somewhere real and you don't see any of the placeholder text in the live UI.",
    },
  },
  {
    id: "security-scanner",
    number: 3,
    title: "Run the Security & Privacy Scanner",
    category: "Security",
    priority: "critical",
    timeEstimate: "1 hr",
    prompt:
      "Act as a senior application security engineer. Audit this entire project end-to-end for the most common ways an early-stage app gets hacked or embarrassed in public. Check for: (1) leaked secrets in code, env files, or git history; (2) outdated dependencies with known CVEs; (3) unsafe code patterns (eval, raw shell exec, SQL string concatenation, unsanitized HTML rendering); (4) any file or asset that should never be deployed (test fixtures with real user data, debug endpoints, .DS_Store, .env, sample API keys); (5) overly permissive defaults (CORS *, public S3 buckets, open admin routes). For each finding, output: severity (Critical/High/Medium/Low), one-sentence plain-English description, exact file and line, and recommended fix. Do NOT fix anything yet — give me the full report sorted by severity, then wait for me to approve fixes one batch at a time.",
    what: "Most modern AI builders (Replit, Lovable, Bolt, Cursor, etc.) ship with a security scanner — a one-click check that goes through your whole project and looks for the common ways apps get hacked, leak data, or accidentally ship dangerous files. Think of it as a smoke detector for your code: it can't fix problems for you, but it tells you exactly where they are before your users find them.",
    why: "You don't know what you don't know. A scanner catches the obvious dangerous stuff — leaked passwords, outdated libraries with known holes, code patterns that hackers automate against — so you stop those before opening the doors. If your builder doesn't ship one, you can run a free equivalent (Snyk, Semgrep).",
    steps: [
      'Open your builder and look for a "Security Scanner," "Audit," or "Vulnerabilities" panel — it usually has its own tab. If yours doesn\'t have one, install Snyk or Semgrep (both free for small projects).',
      "Click Run and let it finish. It usually takes a few minutes; longer for big projects.",
      "Sort by severity and look at everything marked Critical or High first. Ignore Low for now.",
      "For each finding, click into it. The scanner explains what's wrong in plain language and often suggests a fix. If you don't understand a finding, paste it into your AI builder and ask \"what does this mean and how do I fix it?\"",
      "Run your builder's own scanner too — Cursor, Claude Code, Lovable, Replit, Bolt, Snyk, Semgrep, or whatever your stack exposes. Treat it as the final gate after the manual checks, not a substitute for them.",
      "Re-run the scanner after each batch of fixes. You want zero Critical and as few High as possible before launch.",
    ],
    redFlags: [
      "Any Critical finding you can't explain in your own words",
      'High-severity issues you\'re planning to "deal with later"',
      'A long list of "hidden" or "ignored" issues with no notes on why',
      "Your AI builder has a security/audit panel and you have never opened it",
      "Findings that show your app sending user data to companies you didn't intend",
      "Files flagged as malicious or unsafe that you don't recognize",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "shippingszn IS the security scanner referenced by this item. Running `npx shippingszn` and reading the report is the act of completing this checklist item. Mark it complete after a clean scan + reviewing findings.",
  },
  {
    id: "secrets",
    number: 4,
    title: "Lock up your API keys and passwords",
    category: "Security",
    priority: "critical",
    timeEstimate: "1 hr",
    prompt:
      "Act as a security engineer. Scan my entire codebase (including config, scripts, tests, frontend, build output, and any committed .env files) for hardcoded secrets — API keys, tokens, database passwords, OAuth client secrets, webhook signing keys, JWT signing keys, anything that should be private. Classify every key as public-safe or secret-only: publishable Stripe keys, Supabase anon keys, and other documented browser keys may live in the frontend; service-role keys, Stripe secret keys, OpenAI/Anthropic keys, database URLs, webhook secrets, OAuth client secrets, and signing keys must stay server-side only. For each finding, tell me: file, line, what kind of secret it appears to be, and which service it's for. Then refactor every secret-only finding to read from environment variables with clear names (OPENAI_API_KEY, STRIPE_SECRET_KEY, DATABASE_URL, etc.), and update any .env.example or docs to list the required variables without values. Also audit runtime leakage paths: any console.log / logger call that prints req.body, req.headers, full user objects, OAuth callback params, or error objects containing tokens; any Sentry (or equivalent) breadcrumbs that capture request bodies or auth headers without scrubbing; any TODO/debug comments that quote a real key. List every secret that needs to be ROTATED at the source service because it was previously committed, shared, logged, screenshotted, or pasted into chat. Never print actual secret values back to me — only references and filenames.",
    what: "Every app you build talks to other services — Stripe for payments, OpenAI for AI, your database for data. Each of those gives you a long secret string (an API key) that proves it's you. If those strings are sitting inside your code, anyone who looks at your code can use them. That includes anyone you accidentally share a screenshot with, anyone you push to GitHub, and anyone who gets into your builder account.",
    why: 'This is the #1 way AI-built apps get destroyed. One leaked OpenAI key can rack up thousands of dollars over a weekend. One leaked Stripe key can let someone refund every charge you\'ve ever made. Every modern builder gives you a place to store these safely — usually called "Secrets," "Environment Variables," or ".env" — you just have to use it.',
    steps: [
      "Find the Secrets / Environment Variables panel in your builder (usually a lock or key icon in the sidebar). Replit calls it Secrets, Vercel calls them Environment Variables, Bolt calls it .env, etc.",
      'Search your code for anything that looks like a long random string — things starting with "sk-", "AIza", or any variable named "API_KEY", "SECRET", "TOKEN", or "PASSWORD".',
      "Separate public keys from secret keys. Publishable Stripe keys and Supabase anon keys can be browser-visible when provider docs say so; service-role keys, secret keys, AI keys, database URLs, and signing secrets cannot.",
      "Run a git-history scan, not just a search through current files. Tools like gitleaks (free, one command: `gitleaks git .`) check every commit you've ever made — including ones where you 'removed' the key by editing the file. A removed key still lives in history forever, and bots scrape public GitHub for these patterns within minutes of a push.",
      'For each one, add it to Secrets / env vars with a clear name (like OPENAI_API_KEY), then ask your AI builder: "replace the hardcoded OPENAI_API_KEY in my code with the environment variable."',
      "Test that the app still works after the swap.",
      "If a key was ever committed to GitHub (even a private repo), screenshotted, or pasted into a chat — treat it as already-leaked. Go to that service's dashboard, regenerate the key, and update the new value in your env vars. Just deleting the old code does NOTHING — bots scan public GitHub within minutes, and 'private' repos go public by accident more than you'd guess. Rotate first, scrub history second.",
    ],
    redFlags: [
      "You can search your project files and find an actual API key sitting in plain text",
      "A database connection URL with the password right in it, in code",
      "A VITE_ / NEXT_PUBLIC_ / EXPO_PUBLIC_ variable whose name includes SECRET, TOKEN, PASSWORD, PRIVATE, SERVICE_ROLE, or ADMIN",
      "A Supabase service-role key, Stripe secret key, OpenAI key, Anthropic key, webhook secret, OAuth client secret, or database URL visible in frontend code",
      "You've pasted real keys into chats, screenshots, or AI prompts and never rotated them",
      "Your .env or secrets file is sitting in your GitHub history",
      "You've never run gitleaks (or any history scanner) — only searched current files",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "Your codebase contains what looks like a hardcoded API key or password. The scanner found a string that matches a common provider's secret format (OpenAI, Anthropic, Stripe, AWS, GitHub, etc.) sitting directly in source code or a committed config file.",
      whyItBlocksLaunch:
        "A leaked production key is the single fastest way to lose money or expose user data. Public-repo secrets get scraped within minutes of being committed, and the bots that find them spin up paid API calls or exfiltrate database content before you notice. Even private repos leak — screenshots, accidental publishes, and shared chat threads all count.",
      fixInstructions:
        "Move every detected secret-only value out of source into environment variables (OPENAI_API_KEY, STRIPE_SECRET_KEY, DATABASE_URL, etc.) and read them at runtime via process.env. Browser-visible public keys are allowed only when provider docs explicitly mark them publishable or anonymous; everything else moves behind a backend endpoint or serverless function. Add variable names to .env.example without values. Then ROTATE the original secret at the provider — the leaked value must be considered compromised. Update .gitignore to exclude .env, and run gitleaks across history to catch earlier commits.",
      aiBuilderPrompt:
        "Find every hardcoded credential in this project (API keys, tokens, OAuth client secrets, JWT signing keys, webhook secrets, database passwords). For each: tell me the file, the line, what kind of credential it is, and whether provider docs say it is public-safe or secret-only. Refactor every secret-only credential to read from process.env with a clear name (OPENAI_API_KEY, STRIPE_SECRET_KEY, etc.) or move the action behind a backend endpoint. Add every required variable name to .env.example without values. Make sure .env is in .gitignore. List every secret value that needs to be ROTATED at the source service. Never print actual secret values back to me — only references.",
      verificationStep:
        "Run `npx shippingszn` again and confirm zero findings under `secrets`. Run `gitleaks git .` to scan full git history (or `gitleaks dir .` for just the working tree). Rotate any value that ever appeared in a commit, screenshot, or chat — even removing it from current code doesn't unrotate it.",
    },
  },
  {
    id: "api-spend-cap",
    number: 5,
    title: "Cap every AI / API spend before someone bankrupts you",
    category: "Operations",
    priority: "critical",
    timeEstimate: "2 hr+",
    prompt:
      "Act as a senior backend engineer. Audit my app for every paid third-party API I call (OpenAI, Anthropic, Replicate, ElevenLabs, Twilio, Resend, SendGrid, scraping, search, image generation, transcription, anything per-request). For each one: (1) tell me whether the provider's dashboard offers a TRUE hard spending cap or only an alert/notification, where to set the strongest limit it has, and what number to start with — recommend a sane default for an early-stage app. Important: some dashboard 'budgets' (OpenAI's monthly budget among them) only notify you and let the bill keep running, so for those tell me how to enforce a real cap another way — prepaid credits with auto-recharge turned OFF, or a per-key cost cutoff at a gateway in front of the provider; (2) set dashboard alerts at 50% and 80% of that cap where the provider supports alerts; (3) add an in-app per-user daily and per-IP daily quota for that endpoint, plus a max input/output token cap per request (token-priced endpoints can be drained by a few max-length requests even under a normal rate limit), returning a polite 429 when exceeded; (4) add a global kill-switch I can toggle via env var to instantly stop calls if costs spike; (5) log every paid call with user ID, route, token count or unit cost so I can see who is consuming what; (6) add a simple cost dashboard or weekly email summary. After you're done, tell me the absolute worst-case daily spend if my app got pounded by a bot.",
    what: "Every AI API and paid third-party service charges per request. If your app calls OpenAI, Anthropic, Replicate, ElevenLabs, Twilio, or anything similar, an attacker (or a bug) can run those calls in a loop and turn your free trial into a four-figure bill overnight. Spend caps and per-user quotas are the seatbelts.",
    why: "This is one of the most underrated risks for AI-built apps. AI builders happily wire up an OpenAI key for you with no quotas. One infinite loop, one abusive script, one curious user — or one stolen key (theft of AI API keys spiked sharply, and a single leaked key has run up five-figure bills overnight) — can rack up $1K–$10K in a weekend. The provider will not refund it. And don't assume the dashboard budget saves you: several providers, OpenAI included, made their monthly 'budget' notification-only, so it warns you while the spend keeps going. The real cap has to be one you enforce — prepaid credits with auto-recharge off, or your own per-key cost cutoff — plus per-user quotas. Those cost nothing and take minutes to set.",
    steps: [
      "Log into every paid API dashboard (OpenAI, Anthropic, Replicate, etc.) and set the lowest spending limit it offers. Start low — you can raise it. But check whether it's a true hard cap or only an alert: several providers' 'budgets' (OpenAI's included) just notify you and keep charging. Where there's no real hard stop, use prepaid credits with auto-recharge turned OFF, or enforce a per-key cost cutoff at a gateway in front of the provider.",
      "Set dashboard alerts before the cap, at minimum 50% and 80%, so you hear about abuse before the provider shuts off the service or the bill lands.",
      "In your app, add per-user quotas: 'this user can make at most N AI requests per day.' Even logged-in users need this.",
      "Add per-IP rate limits on AI endpoints, separate from your normal API rate limits — much stricter.",
      "Add a global kill-switch (an env variable like AI_ENABLED=false) you can flip in 10 seconds if costs spike.",
      "Log every paid call with user ID and rough cost so you can see who is burning money. Set up a weekly summary email.",
    ],
    redFlags: [
      "No spending cap set in your AI provider's dashboard",
      "Only a warning email exists — no hard cap, quota, or kill switch",
      "No alert before the cap is hit",
      "No per-user limit on your AI features — anyone signed up can call them unlimited times",
      "AI endpoints exposed to logged-out users without strict per-IP limits",
      "You can't quickly answer 'what's the worst case my AI bill could be tomorrow?'",
      "No way to instantly stop AI calls if you see costs spike",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found calls to a paid API (an AI model, image/audio generation, SMS/email, scraping, or similar) with no visible guardrail around them — no per-user quota, no rate limit, and no kill-switch. Right now anything that can reach that endpoint can call the paid provider as fast as it wants, on your bill.",
      whyItBlocksLaunch:
        "This is the fastest way an AI-built app turns into a surprise four- or five-figure bill. An infinite loop, an abusive script, or a stolen key can drain a paid API over a weekend, and the provider won't refund it. Worse, some dashboard 'budgets' (OpenAI's included) only notify you — they don't hard-stop the spend — so the cap you think you set may not exist.",
      fixInstructions:
        "Add a hard limit you actually control: prepaid credits with auto-recharge OFF, or a per-key cost cutoff at a gateway in front of the provider. Then add per-user daily quotas and a max input/output token cap per request, and a global kill-switch (an env flag) you can flip to stop all paid calls in seconds. Log every paid call with a user id and rough cost so you can see who is spending.",
      aiBuilderPrompt:
        "Find every call to a paid third-party API in this project (AI models, image/audio generation, Twilio, email, scraping, search). For each, add: a per-user daily quota and a max input/output token cap per request that returns a 429 when exceeded; a global kill-switch via env var that stops all paid calls; and logging of user id + rough cost per call. Tell me where to set a real hard spend cap for each provider (prepaid credits with auto-recharge off, or a gateway cutoff) and note any provider whose dashboard budget is only a notification. Then tell me the worst-case daily spend if a bot hammered the app. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm zero findings under `api-spend-cap`. Then hit an AI endpoint in a loop as one user and confirm it starts returning 429 once the quota is hit, and confirm flipping the kill-switch env var immediately stops paid calls.",
    },
  },
  {
    id: "secure-auth",
    number: 6,
    title: "Use a real login system, not one you wrote yourself",
    category: "Security",
    priority: "critical",
    timeEstimate: "2 hr+",
    prompt:
      "Act as a senior application security engineer. I want to replace any custom or partial authentication in this app with a battle-tested provider. First, recommend the best fit for my stack from: Clerk, Auth0, Supabase Auth, Stytch, or my platform's built-in auth — and explain why in one paragraph. Then implement it end-to-end: signup, login, logout, password reset, email verification, session management, and protected routes (both pages and API). Use the provider's recommended secure defaults. Add server-side checks on every protected route — never trust the frontend. Add login and OTP rate limiting (max 5 attempts per 15 minutes per IP+identifier). If email or SMS one-time codes are used, normalize phone numbers to E.164, make resend/cooldown behavior explicit, use anti-enumeration responses, write clear mobile copy, verify real code delivery, handle double-clicked/expired verification links gracefully, and add a recovery path if paid access depends on OTP. Set session expiry to 24h of inactivity. Migrate any existing user data safely. After you're done, give me a checklist of what I need to verify in the provider dashboard before launch.",
    what: "How users sign in, receive verification codes, recover paid access, and stay signed in. Done well, only the real user can get into their account. Done badly, an attacker can guess codes, enumerate customers, abuse SMS/email delivery, steal sessions, or read passwords straight out of your database.",
    why: "If your login or OTP flow is weak, every other security thing you did doesn't matter — the attacker just walks in the front door or your paid users get locked out. The good news: you almost never need to build login from scratch. Use a proven provider and let shippingszn scan for the launch risks AI builders usually miss.",
    steps: [
      "Use a real auth provider (Clerk, Auth0, Supabase Auth, Stytch, or your platform's built-in auth like Replit Auth) instead of writing it yourself. Your AI builder can wire one up in a single prompt.",
      "Never store passwords directly. Real auth providers store a one-way scrambled version (a hash) so even they can't read it.",
      "Turn on rate limiting on login (max 5 wrong attempts in 15 minutes) so attackers can't sit there guessing forever.",
      "If you use email or SMS OTP, normalize phone numbers, add resend cooldown copy, use generic success-shaped start responses, and smoke a real delivered code before launch.",
      "Make expired, reused, and double-clicked verification links land in a safe state instead of throwing a scary error or leaking account state.",
      "If paid report or purchase access depends on OTP, add a recovery path: alternate contact, receipt/support handoff, or purchase history.",
      "Set sessions to expire (12–24 hours is normal) so a stolen laptop doesn't mean a permanent account takeover.",
      "Offer two-factor authentication (2FA) if your auth provider supports it — most do, with one toggle.",
    ],
    redFlags: [
      "You can see actual passwords in your database (real ones look like long random gibberish)",
      "You can try the wrong password 100 times in a row and nothing stops you",
      "Sessions never expire — once you log in, you're logged in forever",
      "Your login page works over plain http://, not https://",
      "You wrote login from scratch instead of using a provider",
      "SMS OTP compares raw phone strings instead of normalized E.164 numbers",
      "The OTP start screen reveals whether an email, phone, purchase, or report exists",
      "Paid users have no fallback when the email or SMS code does not arrive",
      "Verification links break when clicked twice, opened on mobile, or opened after expiry",
      "Session cookies missing HttpOnly, Secure, or SameSite (check Application → Cookies in dev tools)",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found gaps in your authentication or one-time-code (OTP) flow. Common detections: phone numbers compared as raw strings instead of normalized E.164, missing resend/cooldown copy on OTP screens, anti-enumeration responses that reveal whether an account exists, no recovery path when paid access depends on OTP, no mobile one-time-code input attribute, or no evidence of a real delivered-code smoke test.",
      whyItBlocksLaunch:
        "Auth and OTP bugs are the #1 way paid users get locked out of products they paid for. A user who can't receive their login code on launch day is a refund and a lifetime negative review. An OTP flow that reveals existing accounts is a free customer list for attackers. These bugs are invisible until production traffic hits.",
      fixInstructions:
        "Use a real auth provider (Clerk, Auth0, Stytch, Supabase Auth) instead of a hand-rolled flow. Normalize phone numbers to E.164 before storing or comparing. Add explicit resend-cooldown copy on the OTP screen. Use generic 'we sent a code if that account exists' responses (anti-enumeration). Add inputmode=numeric and autocomplete=one-time-code to the mobile input. Test a real delivered code from production-similar settings before launch. Add a recovery path (alternate contact, support handoff) if paid access ever depends on OTP.",
      aiBuilderPrompt:
        'Audit this app\'s authentication and OTP flow against the shippingszn `secure-auth` checks. (1) Replace any hand-rolled login with Clerk/Auth0/Stytch/Supabase Auth. (2) Normalize all phone numbers to E.164 at the boundary. (3) Add resend-with-cooldown copy on the OTP screen. (4) Make the OTP-start response identical whether the account exists or not. (5) Add `inputmode="numeric"` and `autocomplete="one-time-code"` to the OTP input. (6) Add a recovery path for users who can\'t receive OTP and have already paid. (7) Verify session cookies are HttpOnly + Secure + SameSite=Lax. Show me the diff before applying.',
      verificationStep:
        "Send yourself a real OTP from production-similar settings — confirm it lands in inbox/SMS within 60 seconds. Try the wrong code 6 times — confirm rate limiting kicks in. Try an account that doesn't exist — confirm the start screen looks identical to the success path. Re-run the scanner and confirm `secure-auth` is clean.",
    },
  },
  {
    id: "common-attacks",
    number: 7,
    title: "Block the most common automated attacks",
    category: "Security",
    priority: "critical",
    timeEstimate: "2 hr+",
    prompt:
      "Act as a security auditor. Audit my full app against the OWASP Top 10, focusing on: (1) SQL injection — find any place I'm building queries with string concatenation or user input that bypasses my ORM's parameterization; (2) NoSQL injection (Mongo, Firestore) — any place user input becomes a filter object without validation; (3) command injection — any place user input reaches a shell-invocation API in my language (Node shelling out, Python shell wrappers, Ruby backticks, etc.); (4) LDAP injection if I talk to a directory service; (5) XSS — find any place user input is rendered as HTML without escaping (innerHTML, raw HTML props, v-html, raw template interpolation, legacy doc-write APIs); (6) CSRF — find any state-changing endpoint without CSRF protection or SameSite cookies; (7) SSRF — find any place user input becomes a URL my server fetches; (8) insecure deserialization; (9) open redirects; (10) file upload handling — verify every upload path enforces a MIME allowlist, max size, path-traversal-safe filenames, and stores outside the web root (or on object storage with no public list); (11) verbose error responses — verify NODE_ENV (or equivalent) is 'production' in production and no stack trace, ORM dump, SQL query, table name, column name, internal service URL, or absolute file path ever leaks to an end-user response body. For each finding: file, line, severity, plain-English explanation, exact fix. Apply the fixes after listing them. Then add a Content Security Policy header tuned to my actual asset sources — no wildcards, minimal unsafe-inline, justify any exception.",
    what: "There are a handful of attacks that bots constantly run against every site on the internet. They have ugly names — XSS, SQL injection, CSRF — but the idea is simple: they trick your app into running code or queries it shouldn't. Modern frameworks have built-in defenses; you just have to use them correctly.",
    why: "These bots don't care who you are. They scan the entire internet looking for sites that forgot to defend. If yours is one of those, your data ends up dumped on a forum, your users get hijacked, and you find out by reading about yourself online.",
    steps: [
      "Never paste user input directly into a database query. Use the safe parameterized version your framework provides (your AI builder knows how — ask it).",
      "Never paste user input directly into HTML you display to other users. Frameworks like React handle this safely by default — don't disable that behavior.",
      "Add a Content Security Policy header (your AI builder can set this up in one prompt) that tells browsers what code they're allowed to run.",
      "Use anti-CSRF tokens on forms that change data, if your auth provider doesn't already handle them.",
      "Show generic errors to users and log detailed errors server-side. Users should never see SQL, table names, stack traces, service URLs, or raw exception text.",
      'Ask your AI builder: "audit my app for XSS, SQL injection, and CSRF vulnerabilities and fix any you find."',
    ],
    redFlags: [
      "Anywhere you're building SQL queries by gluing strings together",
      "Anywhere user input gets shown back to other users without going through the framework's safe rendering",
      "Your framework is showing security warnings in the console you've been ignoring",
      "Forms that change data (delete, update, transfer money) work fine when called from random other websites",
      "Production errors show stack traces, table names, SQL snippets, ORM errors, absolute file paths, or internal service URLs",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner caught a code pattern that maps to a well-known automated attack: unsafe HTML rendering (XSS), wildcard CORS (any origin can call your API), runtime code-execution calls, or a SQL/NoSQL query built from string concatenation instead of parameterization.",
      whyItBlocksLaunch:
        "These are not theoretical. Bots scan the entire internet looking for sites that forgot to use the framework's safe defaults. Your app is one bot away from a stolen session, a hijacked admin route, or a customer-data dump on a forum. The fix is almost always a one-line change to use the framework's safe primitive instead of the raw one.",
      fixInstructions:
        "Replace unsafe HTML rendering APIs (innerHTML, raw HTML props, v-html, legacy doc-write APIs) with the framework's safe interpolation (React's default {}, Vue's {{ }}, etc.). Replace wildcard CORS (`*`) with an explicit allowlist of trusted origins. Eliminate runtime code-execution calls — there is almost always a parser or DSL that does the job safely. Use parameterized queries everywhere — never glue strings into SQL/NoSQL filters. Return generic user-facing errors and log detailed exceptions only server-side. Add a Content Security Policy header tuned to your actual asset origins.",
      aiBuilderPrompt:
        "Audit every finding in this scan tagged `common-attacks`. For each: explain in plain English what the attack is, show me the exact line, and apply the smallest safe fix — escape HTML rather than disabling sanitization, parameterize queries rather than string-glue, narrow CORS to the actual production origin(s), replace runtime code-execution calls with a typed parser. Also add a Content Security Policy header that allowlists ONLY my actual asset origins (no wildcards, minimal unsafe-inline, justify every exception). Show me the diff before applying.",
      verificationStep:
        "Re-run the scanner and confirm zero findings tagged `common-attacks`. In the deployed app, open dev-tools Network and confirm responses include a tight CSP header. Try posting a `<script>alert(1)</script>` payload anywhere user content is rendered — confirm it shows as text, not as an executed alert.",
    },
  },
];
