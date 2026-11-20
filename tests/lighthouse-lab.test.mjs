import { describe, expect, it } from "vitest";
import {
  validateLighthouseReport, summarizeLighthouseRuns, validateLighthousePort,
  hasOwnVitePreviewUrl, extractOwnVitePreviewUrl
} from "../scripts/lighthouse-lab-metrics.mjs";

function report(score=0.86, fcp=800, lcp=1200, cls=0.02, tbt=42) {
  return {
    finalDisplayedUrl: "http://127.0.0.1:4181/",
    requestedUrl: "http://127.0.0.1:4181/",
    lighthouseVersion: "13.6.0",
    runtimeError: undefined,
    categories: { performance: { score } },
    audits: {
      "first-contentful-paint": { numericValue: fcp },
      "largest-contentful-paint": { numericValue: lcp },
      "cumulative-layout-shift": { numericValue: cls },
      "total-blocking-time": { numericValue: tbt }
    }
  };
}
describe("PERF-003 Lighthouse fail-closed local report", () => {
  it("recognizes its own CI-colored Vite URL and rejects foreign startup text", () => {
    const own = "http://127.0.0.1:4181/";
    const colored =
      "  \u001b[32m➜\u001b[39m  \u001b[1mLocal\u001b[22m:   " +
      "\u001b[36mhttp://127.0.0.1:\u001b[1m4181\u001b[22m/\u001b[39m\n";
    expect(hasOwnVitePreviewUrl(colored, own)).toBe(true);
    expect(hasOwnVitePreviewUrl("  ➜  Local:   " + own + "\n", own)).toBe(true);
    expect(hasOwnVitePreviewUrl("  ➜  Local:   http://127.0.0.1:4182/\n", own)).toBe(false);
    expect(hasOwnVitePreviewUrl("text only " + own + "\n", own)).toBe(false);
    expect(hasOwnVitePreviewUrl("  ➜  Local:   https://outside.invalid/\n", own)).toBe(false);
  });

  it("extracts only the actual localhost URL from Vite-owned startup, including ephemeral port", () => {
    const colored="  ➜  Local:   \u001b[36mhttp://127.0.0.1:\u001b[1m38619\u001b[22m/\u001b[39m\n";
    expect(extractOwnVitePreviewUrl(colored)).toBe("http://127.0.0.1:38619/");
    expect(hasOwnVitePreviewUrl(colored, "http://127.0.0.1:38619/")).toBe(true);
    expect(hasOwnVitePreviewUrl(colored, "http://127.0.0.1:4181/")).toBe(false);
    for (const forged of [
      "  ➜  Local:   http://127.0.0.1:80/\n",
      "  ➜  Local:   http://127.0.0.1:65536/\n",
      "  ➜  Local:   http://127.0.0.1:03861/\n",
      "  ➜  Local:   http://127.0.0.1:38619/evil\n",
      "  ➜  Local:   https://127.0.0.1:38619/\n",
      "  ➜  Local:   http://localhost:38619/\n",
      "untrusted text Local:   http://127.0.0.1:38619/\n",
      "  ➜  Local:   http://127.0.0.1:38619/\n  ➜  Local:   http://127.0.0.1:38620/\n"
    ]) expect(extractOwnVitePreviewUrl(forged)).toBeNull();
  });

  it("requires strictly validated unprivileged ports", () => {
    // An unspecified port now delegates to Vite/OS; validation applies only to explicit overrides.
    expect(() => validateLighthousePort(undefined)).toThrow(/FOLIO_LIGHTHOUSE_PORT/);
    expect(validateLighthousePort("4519")).toBe(4519);
    for(const bad of ["", "80", "0", "1023", "65536", "8080 ", " 8080", "08e4", "99999", "notaport"])
      expect(() => validateLighthousePort(bad)).toThrow(/FOLIO_LIGHTHOUSE_PORT/);
  });
  it("rejects incomplete, redirected and failed Lighthouse reports", () => {
    const ok = report();
    expect(validateLighthouseReport(ok, "http://127.0.0.1:4181/")).toEqual({
      score: 86, fcpMs: 800, lcpMs: 1200, cls: .02, tbtMs: 42
    });
    for (const bad of [
      { ...ok, finalDisplayedUrl: "https://example.com/" },
      { ...ok, runtimeError: { code: "FAILED_DOCUMENT_REQUEST" } },
      { ...ok, categories: { performance: { score: null } } },
      { ...ok, audits: { ...ok.audits, "largest-contentful-paint": { numericValue: null } } },
      { ...ok, audits: { ...ok.audits, "first-contentful-paint": { numericValue: 0 } } },
      { ...ok, audits: { ...ok.audits, "cumulative-layout-shift": { numericValue: -1 } } }
    ]) expect(() => validateLighthouseReport(bad, "http://127.0.0.1:4181/")).toThrow();
  });
  it("requires three actual runs and returns median without invented metrics", () => {
    const u="http://127.0.0.1:4181/";
    expect(() => summarizeLighthouseRuns([report(), report()], u)).toThrow(/three/i);
    const stats = summarizeLighthouseRuns([
      report(.6, 900, 1400, .03, 95),
      report(.8, 700, 1100, .02, 65),
      report(.7, 800, 1200, .01, 75)
    ],u);
    expect(stats).toEqual({
      runs: 3,
      median: { score: 70, fcpMs: 800, lcpMs: 1200, cls: .02, tbtMs: 75 }
    });
  });
});
