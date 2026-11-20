import type { Category, Priority, TimeEstimate } from "./types.js";

export const TIME_ESTIMATE_ORDER: TimeEstimate[] = [
  "5 min",
  "15 min",
  "30 min",
  "1 hr",
  "2 hr+",
];

export const TIME_ESTIMATE_MINUTES: Record<TimeEstimate, number> = {
  "5 min": 5,
  "15 min": 15,
  "30 min": 30,
  "1 hr": 60,
  "2 hr+": 120,
};

export const PRIORITY_LABELS: Record<Priority, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  lower: "Lower",
};

export const PRIORITY_SUBLABELS: Record<Priority, string> = {
  critical: "ship-stoppers",
  high: "high",
  medium: "launch quality",
  lower: "post-launch growth",
};

export const PRIORITY_DESCRIPTIONS: Record<Priority, string> = {
  critical:
    "Don't ship without these. These are how AI-built apps get hacked, sued, or embarrassed in public.",
  high: "Handle these in the first week. The basics that keep your app alive, debuggable, and trustworthy.",
  medium:
    "Polish that turns a launch into something people stick with. Do these as you grow.",
  lower:
    "Once people are using it, this is how you keep them and find more of them.",
};

export const PRIORITY_ORDER: Priority[] = [
  "critical",
  "high",
  "medium",
  "lower",
];

export const CATEGORIES: Category[] = [
  "Security",
  "Infrastructure",
  "Operations",
  "Product & Launch",
  "Growth",
];
