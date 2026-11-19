import { defineConfig, devices } from "@playwright/test";

/**
 * Real Chromium rendering; the synthetic API is intercepted inside test
 * contexts. Never connects to Cloudflare Preview or production resources.
 */
export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 8_000 },
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:4175",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    actionTimeout: 8_000
  },
  projects: [
    { name: "chromium-desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1366, height: 900 } } },
    { name: "chromium-mobile", use: { ...devices["Pixel 7"] } },
    { name: "chromium-reflow-320", use: { ...devices["Desktop Chrome"], viewport: { width: 320, height: 640 } } }
  ],
  webServer: {
    command: "pnpm --dir apps/web exec vite --host 127.0.0.1 --port 4175 --strictPort",
    url: "http://127.0.0.1:4175",
    reuseExistingServer: false,
    timeout: 45_000
  }
});
