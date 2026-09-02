export type Severity = "critical" | "high" | "medium" | "lower";

export interface ChecklistItemRef {
  id: string;
  title: string;
  priority: Severity;
}

export const CHECKLIST_ITEMS: Record<string, ChecklistItemRef> = {
  secrets: {
    id: "secrets",
    title: "Lock up your API keys and passwords",
    priority: "critical",
  },
  "common-attacks": {
    id: "common-attacks",
    title: "Block the most common automated attacks",
    priority: "critical",
  },
  "https-headers": {
    id: "https-headers",
    title: "Force HTTPS and add browser-level defenses",
    priority: "critical",
  },
  "dev-prod-data": {
    id: "dev-prod-data",
    title: "Keep your test data away from real users",
    priority: "critical",
  },
  "secure-auth": {
    id: "secure-auth",
    title: "Use a real login system, not one you wrote yourself",
    priority: "critical",
  },
  "api-spend-cap": {
    id: "api-spend-cap",
    title: "Cap every AI / API spend before someone bankrupts you",
    priority: "critical",
  },
  "rate-limiting": {
    id: "rate-limiting",
    title: "Cap how often someone can hit your app",
    priority: "high",
  },
  "error-monitoring": {
    id: "error-monitoring",
    title: "Get notified the moment something breaks",
    priority: "high",
  },
  "legal-pages": {
    id: "legal-pages",
    title: "Add real Terms and Privacy pages (don't fake these)",
    priority: "critical",
  },
  payments: {
    id: "payments",
    title: "Make sure payments actually work before you charge people",
    priority: "critical",
  },
  "file-uploads": {
    id: "file-uploads",
    title: "Lock down uploads and private files",
    priority: "critical",
  },
  "session-management": {
    id: "session-management",
    title: "Make sessions feel safe AND convenient",
    priority: "high",
  },
  "secure-api": {
    id: "secure-api",
    title: "Lock down your app's behind-the-scenes URLs",
    priority: "critical",
  },
  github: {
    id: "github",
    title: "Connect to GitHub for backups and history",
    priority: "high",
  },
  seo: {
    id: "seo",
    title: "Set up the basics so search and social shares work",
    priority: "medium",
  },
  "launch-polish": {
    id: "launch-polish",
    title: "Walk through the whole app one last time",
    priority: "medium",
  },
  "ai-audit": {
    id: "ai-audit",
    title: "Audit what your AI builder actually shipped",
    priority: "critical",
  },
  aeo: {
    id: "aeo",
    title: "Make AI assistants able to recommend you",
    priority: "lower",
  },
  "installable-app": {
    id: "installable-app",
    title: "Make your app installable on phones",
    priority: "lower",
  },
  "model-freshness": {
    id: "model-freshness",
    title: "Verify every AI model ID your app calls still exists",
    priority: "critical",
  },
  "dependency-integrity": {
    id: "dependency-integrity",
    title: "Confirm every package your AI added is real",
    priority: "high",
  },
};

export function permalinkFor(itemId: string, baseUrl: string): string {
  const trimmed = baseUrl.replace(/\/+$/, "");
  return `${trimmed}/i/${itemId}`;
}
