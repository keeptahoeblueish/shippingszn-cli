// CLI build: bundle src/index.ts (and everything it imports, including the
// vendored checklist-data / launch-readiness modules under src/vendor) into a
// single dist/index.js suitable for publishing to npm. A plain `tsc` transpile
// would leave the internal module graph as separate files; bundling keeps the
// published package self-contained so `npx shippingszn` runs with no runtime
// dependency resolution beyond Node built-ins.

import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { mkdir, rm, chmod } from "node:fs/promises";
import { build as esbuild } from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
const distDir = resolve(here, "dist");

await rm(distDir, { recursive: true, force: true });
await mkdir(distDir, { recursive: true });

await esbuild({
  entryPoints: [resolve(here, "src/index.ts")],
  outfile: resolve(distDir, "index.js"),
  platform: "node",
  format: "esm",
  bundle: true,
  target: "node20",
  // Externalize only Node built-ins. Everything else (including the vendored
  // modules under src/vendor) gets bundled inline so the published package is
  // self-contained.
  external: ["node:*"],
  // No banner: src/index.ts already starts with `#!/usr/bin/env node`
  // and esbuild preserves it when bundling. Adding our own banner
  // duplicates the shebang and breaks node parsing.
  logLevel: "info",
  sourcemap: false,
});

// Mark the bundle executable so npm's `bin` shim works without an
// explicit `chmod +x` step on install.
await chmod(resolve(distDir, "index.js"), 0o755);

console.log("[cli build] wrote", resolve(distDir, "index.js"));
