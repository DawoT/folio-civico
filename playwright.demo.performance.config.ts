import { defineConfig } from "@playwright/test";
import demo from "./playwright.demo.config";
import { resolveDemoPort } from "./apps/web/demo-port.mjs";

const origin = `http://127.0.0.1:${resolveDemoPort(process.env.FOLIO_DEMO_PORT)}`;

/** Independent, disposable signed-JWT backend for the built-frontend lab. */
export default defineConfig({
  ...demo,
  testDir: "./tests/demo",
  testMatch: "**/real-api.perf.spec.ts",
  testIgnore: [],
  webServer: {
    command: "pnpm demo:local",
    url: `${origin}/__demo`,
    reuseExistingServer: false,
    timeout: 45_000
  }
});
