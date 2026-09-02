import type { ScannedFile } from "../scan.js";
import type { Severity } from "../items.js";

export interface Finding {
  checkId: string;
  itemId: string;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
  evidence?: string;
}

export interface CheckContext {
  rootDir: string;
  files: ScannedFile[];
}
