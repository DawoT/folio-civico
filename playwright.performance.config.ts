import { defineConfig, devices } from "@playwright/test";

// Isolated from the dev E2E (4175) and guided API demo (4176).
const rawPort = process.env.FOLIO_PERF_PORT ?? "4178";
if (!/^[1-9][0-9]{3,4}$/.test(rawPort) || Number(rawPort) < 1024 || Number(rawPort) > 65535) {
  throw new Error("FOLIO_PERF_PORT must be a valid unprivileged TCP port");
}
const origin = `http://127.0.0.1:${rawPort}`;

/** Local production Vite preview, real Chromium, synthetic API responses. */
export default defineConfig({
  testDir: "./tests/performance",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    viewport: { width: 1366, height: 900 },
    locale: "es-PE",
    baseURL: origin,
    trace: "retain-on-failure",
    screenshot: "only-on-failure"
  },
  webServer: {
    command: `pnpm --dir apps/web exec vite preview --host 127.0.0.1 --port ${rawPort} --strictPort`,
    url: origin,
    reuseExistingServer: false,
    timeout: 45_000
  }
});
