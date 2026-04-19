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
  github: {
    id: "github",
    title: "Get your code into GitHub safely",
    priority: "high",
  },
  seo: {
    id: "seo",
    title: "Make sure search engines and link previews work",
    priority: "medium",
  },
  "launch-polish": {
    id: "launch-polish",
    title: "Last-mile launch polish",
    priority: "medium",
  },
  "ai-audit": {
    id: "ai-audit",
    title: "Audit what your AI builder actually shipped",
    priority: "critical",
  },
};

export function permalinkFor(itemId: string, baseUrl: string): string {
  const trimmed = baseUrl.replace(/\/+$/, "");
  return `${trimmed}/i/${itemId}`;
}
