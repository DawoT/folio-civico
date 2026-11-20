import { defineConfig, devices } from "@playwright/test";

// Concurrent local worktrees must not share an occupied test server port.
const rawPort = process.env.FOLIO_E2E_PORT ?? "4175";
if (!/^[0-9]{4,5}$/.test(rawPort) || Number(rawPort) < 1024
  || Number(rawPort) > 65535) {
  throw new Error("FOLIO_E2E_PORT must be a valid unprivileged TCP port");
}
const baseUrl = `http://127.0.0.1:${rawPort}`;

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
    baseURL: baseUrl,
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
    command: `pnpm --dir apps/web exec vite --host 127.0.0.1 --port ${rawPort} --strictPort`,
    url: baseUrl,
    reuseExistingServer: false,
    timeout: 45_000
  }
});
