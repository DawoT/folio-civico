import { defineConfig, devices } from "@playwright/test";

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
    baseURL: "http://127.0.0.1:4176",
    trace: "retain-on-failure",
    screenshot: "only-on-failure"
  },
  webServer: {
    command: "pnpm demo:local",
    url: "http://127.0.0.1:4176/__demo",
    reuseExistingServer: !process.env.CI,
    timeout: 45_000
  }
});
