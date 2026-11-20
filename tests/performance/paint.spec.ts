import { expect, test } from "@playwright/test";
import { SyntheticPilotApi } from "../browser/synthetic-api";
import { summarizeLabMetrics, validateLabSample } from "../../scripts/performance-lab-metrics.mjs";

interface PaintState {
  lcpMs: number | null;
  cls: number;
  supported: boolean;
}

/**
 * Real Chromium + built Vite assets, with a synthetic API double.
 * No network throttling, no field data and no Lighthouse score are implied.
 */
test("PERF-002: capture real cold-navigation paint and layout-shift lab metrics", async ({ browser }) => {
  test.setTimeout(90_000);
  const samples = [];
  for (let iteration = 0; iteration < 3; iteration++) {
    // Each new browser context starts with a new HTTP cache and no cookies.
    const context = await browser.newContext({
      viewport: { width: 1366, height: 900 },
      locale: "es-PE",
      serviceWorkers: "block"
    });
    try {
      const page = await context.newPage();
      const externalRequests: string[] = [];
      page.on("request", req => {
        const url = req.url();
        if (/^https?:\/\//.test(url) && new URL(url).hostname !== "127.0.0.1") {
          externalRequests.push(new URL(url).origin);
        }
      });
      const synthetic = new SyntheticPilotApi();
      await synthetic.attach(page, "author");
      await page.addInitScript(() => {
        const supported = PerformanceObserver.supportedEntryTypes;
        const state: PaintState = {
          lcpMs: null,
          cls: 0,
          supported: supported.includes("largest-contentful-paint")
            && supported.includes("layout-shift")
        };
        (window as Window & { __fcPaintState?: PaintState }).__fcPaintState = state;
        if (!state.supported) return;
        new PerformanceObserver(list => {
          for (const entry of list.getEntries()) state.lcpMs = entry.startTime;
        }).observe({ type: "largest-contentful-paint", buffered: true });
        new PerformanceObserver(list => {
          for (const entry of list.getEntries()) {
            const shift = entry as PerformanceEntry & { value: number; hadRecentInput: boolean };
            if (!shift.hadRecentInput) state.cls += shift.value;
          }
        }).observe({ type: "layout-shift", buffered: true });
      });

      const response = await page.goto("/", { waitUntil: "load" });
      expect(response?.status()).toBe(200);
      await expect(page.getByLabel("Identificador de comisión")).toBeVisible();
      await page.waitForTimeout(250);

      const result = await page.evaluate(() => {
        const state = (window as Window & { __fcPaintState?: PaintState }).__fcPaintState;
        const paints = performance.getEntriesByType("paint");
        const fcp = paints.find(entry => entry.name === "first-contentful-paint");
        const navigation = performance.getEntriesByType("navigation")[0] as
          PerformanceNavigationTiming | undefined;
        return {
          supported: state?.supported ?? false,
          hasProductionJs: Array.from(document.querySelectorAll("script[src]"))
            .some(script => (script as HTMLScriptElement).src.includes("/assets/")),
          hasProductionCss: Array.from(document.querySelectorAll("link[rel=stylesheet]"))
            .some(link => (link as HTMLLinkElement).href.includes("/assets/")),
          sample: {
            ttfbMs: navigation?.responseStart ?? null,
            fcpMs: fcp?.startTime ?? null,
            lcpMs: state?.lcpMs ?? null,
            cls: state?.cls ?? null
          }
        };
      });
      expect(result.supported, "Chromium must support both paint observers").toBe(true);
      expect(result.hasProductionJs, "The server must return the production JS bundle").toBe(true);
      expect(result.hasProductionCss, "The server must return the production CSS bundle").toBe(true);
      expect(externalRequests, "No external traffic is allowed in the lab").toEqual([]);
      samples.push(validateLabSample(result.sample));
    } finally {
      await context.close();
    }
  }
  const report = summarizeLabMetrics(samples);
  expect(report.navigations).toBe(3);
  // Aggregate only: no URLs, subjects, document contents or per-user telemetry.
  console.log("PERF-002 LOCAL CHROMIUM LAB (production build; no throttling): " + JSON.stringify(report));
});
