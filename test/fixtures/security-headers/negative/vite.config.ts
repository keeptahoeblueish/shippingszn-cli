import { defineConfig } from "vite";
import helmet from "helmet";
export default defineConfig({
  server: {
    port: 5173,
    headers: {
      "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
      "Content-Security-Policy": "default-src 'self'",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
    },
  },
  plugins: [helmet()],
});
