import type { ChecklistItem } from "./types.js";

export const ITEMS_LOWER: ChecklistItem[] = [
  {
    id: "aeo",
    number: 48,
    title: "Make AI assistants able to recommend you",
    category: "Growth",
    priority: "lower",
    timeEstimate: "2 hr+",
    prompt:
      "Act as an AEO (answer engine optimization) specialist. Make my site quotable by AI engines (ChatGPT, Perplexity, Google AI Overviews, Claude). Tasks: (1) generate JSON-LD structured data for my homepage (Organization, WebSite) and key pages (Product, FAQPage, Article where applicable) and embed it in <head>; (2) create a real /faq page covering the 10-20 questions a real prospect asks before buying — ask me what my product is so the questions are accurate. Each answer 40-60 words, direct answer first, then context; (3) restructure my main marketing pages so each section starts with a 1-2 sentence summary BEFORE the long explanation (AI engines grab the top); (4) make sure no SEO-important content is gated behind a login or only rendered client-side; (5) confirm my robots.txt and CDN/Cloudflare bot settings don't block the AI answer/search crawlers that would cite me (GPTBot, OAI-SearchBot, ClaudeBot, PerplexityBot) — note that from September 15, 2026 Cloudflare blocks 'Training' and 'Agent' AI crawlers by default on new and free sites' ad-serving pages (Search crawlers stay allowed), so check this deliberately; optionally add an /llms.txt (low-cost but unproven — mainly read by coding agents, not AI search). Test the result with Google's Rich Results Test and report what each page is eligible for.",
    what: "More and more people ask ChatGPT, Perplexity, or Google's AI Overviews instead of clicking through search results. Those AIs are pulling answers from websites \u2014 but only the ones structured in a way they can confidently quote. AEO is the work of making your site quotable.",
    why: 'Search is shifting from "here are 10 links" to "here\'s the answer." If your content isn\'t structured for AI engines to extract, you\'re invisible to a fast-growing channel \u2014 even if your normal SEO is fine.',
    steps: [
      "Add a real FAQ page covering the top 10\u201320 questions people actually ask about your product. Keep answers tight (40\u201360 words each).",
      'Write headings as full questions ("How do I cancel my subscription?" instead of "Cancellation").',
      "Add structured data (JSON-LD) to your pages: at minimum FAQPage schema on the FAQ page and Organization schema on your homepage. Your AI builder can generate these.",
      "Lead each content section with a 1\u20132 sentence direct answer at the top, before the long-form explanation. AIs grab the top.",
      "Make sure important content isn't locked behind login or only rendered by JavaScript \u2014 AI crawlers often miss those.",
      "Make sure you're not accidentally blocking the AI crawlers that would cite you. Check your robots.txt and your CDN/host bot settings — from September 15, 2026 Cloudflare blocks 'Training' and 'Agent' AI crawlers by default on new and free sites' ad-serving pages (Search crawlers stay allowed), so verify your own config lets answer/search bots like GPTBot, OAI-SearchBot, ClaudeBot, and PerplexityBot reach your pages.",
      "Optionally add an /llms.txt file at your site root \u2014 a short plain-text summary of what your site is, who it's for, and links to your sitemap and FAQ. It's a low-cost, emerging convention, but treat it as optional: no major AI engine has confirmed reading it for answers, studies show almost none are ever fetched, and Google has said it doesn't use it. It's most useful for docs/API products that coding agents crawl \u2014 don't count on it for AI-search visibility.",
      "Test your structured data with Google's Rich Results Test \u2014 it tells you what AIs can actually see.",
    ],
    redFlags: [
      "No structured data anywhere on your site",
      "Long-winded content with no short summary at the top",
      "Important content gated behind a login wall",
      "No FAQ section answering the questions people actually ask",
      "Headings that are vague labels instead of clear questions",
      "AI answer/search crawlers (GPTBot, OAI-SearchBot, ClaudeBot, PerplexityBot) blocked by your robots.txt or CDN \u2014 the engines that would cite you can't reach your pages",
      "Content that targets keyword strings instead of full questions people actually ask",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scan found your site isn't structured for AI answer engines — little or no JSON-LD structured data on your key pages, and/or robots.txt or CDN bot rules that could keep the AI answer/search crawlers out. That means engines like ChatGPT, Perplexity, and Google AI Overviews can't confidently quote you.",
      whyItBlocksLaunch:
        "More and more buyers ask an AI assistant instead of clicking through search results, and those engines only cite pages they can extract cleanly. If your content isn't machine-readable — or the crawlers that would cite you are blocked — you're invisible to a fast-growing discovery channel even when your normal SEO is fine.",
      fixInstructions:
        "Add JSON-LD to your pages: at minimum Organization and WebSite on your homepage and FAQPage on a real /faq page, plus Product or Article schema where they apply. Lead each content section with a 1-2 sentence direct answer before the long explanation, and keep launch-important content server-rendered rather than login-gated or JS-only. Then confirm your robots.txt and CDN/Cloudflare bot settings let GPTBot, OAI-SearchBot, ClaudeBot, and PerplexityBot reach your pages, and validate everything with Google's Rich Results Test.",
      aiBuilderPrompt:
        "Make my site quotable by AI answer engines (ChatGPT, Perplexity, Google AI Overviews, Claude). (1) Generate JSON-LD for my homepage (Organization, WebSite) and key pages (Product, FAQPage, Article where applicable) and embed it in <head>. (2) Build a real /faq page answering the 10-20 questions a prospect asks before buying — ask me what my product is first — each answer 40-60 words, direct answer first. (3) Restructure my marketing pages so each section opens with a 1-2 sentence summary before the detail. (4) Make sure no launch-important content is login-gated or only rendered client-side. (5) Confirm my robots.txt and CDN/Cloudflare bot settings don't block GPTBot, OAI-SearchBot, ClaudeBot, or PerplexityBot. Show me the diff before applying, then test with Google's Rich Results Test.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm `aeo` is clean, then run your homepage and /faq page through Google's Rich Results Test and confirm each reports valid structured data.",
    },
  },
  {
    id: "community",
    number: 49,
    title: "Start a small community space",
    category: "Growth",
    priority: "lower",
    timeEstimate: "1 hr",
    prompt:
      "Act as a community-building strategist who has launched multiple successful Discord/Slack communities from zero. Help me set up a small community space for my early users. First, ask me: who are my users (consumers? developers? professionals?), what platform have they used before, and how big do I realistically expect this to get in 90 days. Then output: (1) a recommendation for which platform fits — Discord, Slack, Circle, etc. — with one-paragraph reasoning; (2) a starter channel/category structure (max 5-7 channels — don't over-build); (3) welcome message + rules + onboarding DM I can copy-paste and tweak; (4) a 30-day content plan: what I post each day for the first month so it doesn't go silent; (5) the exact list of 10-20 first people to hand-invite and a script for asking them; (6) red flags to watch for. Be opinionated and concrete — no vague \"engage your community\" platitudes.",
    what: "A central place (Discord, Slack, Circle, or even a private Telegram) where your users can hang out, ask questions, share what they're building with your tool, and run into you.",
    why: "Engaged users become unpaid evangelists, your fastest source of product ideas, and your best customer support. They also stick around longer because they have a relationship, not just a tool.",
    steps: [
      "Pick one platform \u2014 don't spread yourself across three. Discord is most common for early-stage; Slack if your users are professionals.",
      "Hand-invite your first 10\u201320 power users personally. Don't do a public push until there's something there.",
      "Show up daily for the first month. Reply to every message. Welcome every new arrival by name.",
      "Encourage members to help each other \u2014 celebrate it when they do.",
      "Ship visible improvements based on community feedback and shout out the person who suggested it.",
    ],
    redFlags: [
      "Empty server because you started it before having users",
      "You're absent \u2014 community goes silent without you",
      "You're trying to be on Discord AND Slack AND Telegram (pick one)",
      "No moderation plan \u2014 the first troll ruins the vibe for everyone",
      "You ignore feedback even when it's consistent",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "Community quality is about real people, active moderation, and daily founder presence. The scanner cannot prove a Discord or Slack space is alive or useful.",
  },
  {
    id: "iteration",
    number: 50,
    title: "Plan what you'll improve in week 1",
    category: "Growth",
    priority: "lower",
    timeEstimate: "30 min",
    prompt:
      "Act as a product manager helping me build my first post-launch iteration plan. I'll give you: (1) my top 5 pieces of user feedback so far; (2) my top 3 bugs from error monitoring; (3) my top 1-2 drop-off points in analytics. If I haven't given you that data, ask me for it — don't guess. Then build me a one-page plan: (a) the 3 highest impact-per-effort fixes/improvements to do this week; (b) the 2-3 bigger items for next month; (c) the things I should explicitly NOT do right now and why (a \"not now\" list is as important as a to-do list); (d) a one-paragraph changelog template I can publish each Friday so users can see I'm shipping. Be ruthless about scope — I'd rather ship 3 things well than 10 things poorly.",
    what: "A short list of what you'll work on right after launch, based on what you learn from early users and analytics. Not a six-month roadmap \u2014 just \u201Chere are the next three things.\u201D",
    why: "Without a plan you'll either freeze (paralyzed by all the feedback) or thrash (rebuilding the homepage every Monday). A simple iteration loop turns the chaos of launch into measurable forward motion.",
    steps: [
      "After your first week, sit down and review: top 5 pieces of feedback, top 3 bugs from error monitoring, top 1\u20132 drop-off points in analytics.",
      "Pick the 3 things with the highest impact-per-effort. Ignore everything else for now.",
      "Decide which are quick wins (do this week) vs. bigger lifts (next month).",
      "Set a public next-update date so you have a forcing function.",
      "Tell your users what changed when you ship \u2014 they want to know they were heard.",
    ],
    redFlags: [
      'No plan beyond "keep building"',
      "Ignoring obvious problems multiple users have reported",
      "Adding new features no one asked for instead of fixing what's broken",
      "Silent updates \u2014 users don't know you're iterating",
      "Pivoting your whole strategy based on one loud complainer",
    ],
    cliCoverage: "manual_only",
    whyManual:
      "A week-one iteration plan depends on fresh user feedback, analytics, and bug data after launch. The scanner cannot know whether the roadmap reflects what users actually did.",
  },
  {
    id: "installable-app",
    number: 51,
    title: "Make your app installable on phones",
    category: "Product & Launch",
    priority: "lower",
    timeEstimate: "30 min",
    prompt:
      "Act as a frontend engineer. Make my web app a proper Progressive Web App (PWA) so phone users can install it to their home screen. Tasks: (1) create a /manifest.json with name, short_name (≤12 chars), start_url: '/', display: 'standalone', background_color, theme_color matching my brand, and an icons array with at least 192×192 and 512×512 PNGs (generate them from my logo if I don't have them yet — lossless, transparent background). (2) add <link rel='manifest' href='/manifest.json'> and <meta name='theme-color' content='#yourbrand'> to <head>. (3) generate a proper favicon bundle: favicon.ico (multi-size), favicon.svg, apple-touch-icon.png (180×180), and wire them into <head> with <link rel='icon'> and <link rel='apple-touch-icon'>. (4) verify in Chrome DevTools → Application → Manifest that every field validates and the install prompt appears. (5) test on a real phone: open in Safari or Chrome, use Share → 'Add to Home Screen', confirm the app launches full-screen without the browser chrome. Report any warnings from Lighthouse's PWA audit.",
    what: "A tiny /manifest.json plus proper-sized icons lets people add your site to their phone's home screen with one tap. When they launch it, it opens full-screen — no browser URL bar in the way — like a real app. Zero app-store submission needed.",
    why: "Most AI-built sites stop at the default favicon and never get installed. Users who add your app to their home screen return two to three times more often than bookmark-only users — and it's a 30-minute setup to enable it forever. Also closes the subtle credibility gap of a generic browser favicon on your production URL.",
    steps: [
      "Generate your icon set: at minimum a 512\u00d7512 PNG, a 192\u00d7192 PNG, a 180\u00d7180 apple-touch-icon.png, and a favicon.ico or favicon.svg. Transparent backgrounds.",
      "Create a /manifest.json with your app name, short name (\u226412 chars), start URL, standalone display mode, theme color, and the icons.",
      'Link it from <head>: <link rel="manifest" href="/manifest.json"> plus <meta name="theme-color" content="#yourbrand">.',
      'Add <link rel="apple-touch-icon" href="/apple-touch-icon.png"> and <link rel="icon" href="/favicon.svg"> pointing at your icons.',
      "Open Chrome DevTools \u2192 Application \u2192 Manifest and confirm every field validates with no warnings.",
      "Open your site on a real phone, tap Share \u2192 Add to Home Screen, confirm it installs and launches full-screen.",
    ],
    redFlags: [
      "Default browser favicon still showing in the tab",
      "No /manifest.json \u2014 iOS and Android can't install your site",
      "Icons are the framework's starter logo (Next.js, Vite placeholder, etc.)",
      "No apple-touch-icon \u2014 iPhone home-screen icon looks terrible",
      "Manifest exists but references missing or wrong-size icons",
    ],
    cliCoverage: "automated",
    cliPrompt: {
      whatFailed:
        "The scanner found no PWA manifest and/or no proper app icons — your site isn't installable to a phone home screen, and it's likely still showing the framework's starter favicon (the Vite or Next.js placeholder) instead of your own.",
      whyItBlocksLaunch:
        "A generic browser favicon on your production URL is a subtle credibility gap — it reads as unfinished side project. And you're leaving retention on the table: users who add your app to their home screen come back two to three times more often than bookmark-only visitors, and it's a 30-minute setup that pays off forever.",
      fixInstructions:
        "Add a /manifest.json with name, short_name (≤12 chars), start_url of /, display standalone, background_color, and a theme_color matching your brand, plus an icons array with at least 192×192 and 512×512 PNGs. Link it from <head> along with a theme-color meta tag. Generate a real favicon bundle (favicon.ico multi-size, favicon.svg, apple-touch-icon.png at 180×180) from your logo and wire it into <head>. Verify in Chrome DevTools → Application → Manifest that every field validates and the install prompt appears.",
      aiBuilderPrompt:
        "Make this web app installable as a PWA. (1) Create /manifest.json with name, short_name (≤12 chars), start_url of /, display standalone, background_color, brand theme_color, and an icons array with 192×192 and 512×512 PNGs — generate them from my logo if I don't have them. (2) Add a manifest <link> and a theme-color <meta> to <head>. (3) Generate a proper favicon bundle (favicon.ico multi-size, favicon.svg, apple-touch-icon.png 180×180) and wire it into <head>, replacing any framework placeholder. (4) Confirm it validates in Chrome DevTools → Application → Manifest and note any Lighthouse PWA warnings. Show me the diff before applying.",
      verificationStep:
        "Re-run `npx shippingszn` and confirm `installable-app` is clean, then open the site on a phone, use Share → Add to Home Screen, and confirm it installs with your icon and launches full-screen without the browser bar.",
    },
  },
];
