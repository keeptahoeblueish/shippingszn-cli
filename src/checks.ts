/**
 * Backwards-compatible barrel for the scanner checks.
 *
 * The implementation lives in `./checks/`, split per domain (secrets, env,
 * headers, dangerous patterns, language patterns, public assets, content
 * quality). Importers should prefer `./checks/index` directly going forward.
 */
export * from "./checks/index.js";
