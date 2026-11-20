import { defineConfig, devices } from "@playwright/test";
import { resolveDemoPort } from "./apps/web/demo-port.mjs";

const demoPort = resolveDemoPort(process.env.FOLIO_DEMO_PORT);
const demoOrigin = `http://127.0.0.1:${demoPort}`;

/**
 * Actual API handler, RS256 Access-style JWTs, local D1 SQLite and in-memory
 * R2: unlike pilot.spec.ts, this test does not intercept /api/**.
 */
export default defineConfig({
  testDir: "./tests/demo",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    baseURL: demoOrigin,
    trace: "retain-on-failure",
    screenshot: "only-on-failure"
  },
  webServer: {
    command: "pnpm demo:local",
    url: `${demoOrigin}/__demo`,
    reuseExistingServer: false,
    timeout: 45_000
  }
});
