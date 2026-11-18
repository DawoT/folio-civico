import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-plugin";

export default defineConfig({
  plugins: [
    cloudflareTest({ wrangler: { configPath: "./apps/api/wrangler.jsonc" } })
  ],
  test: { include: ["tests/workers/**/*.workers.test.ts"] }
});
