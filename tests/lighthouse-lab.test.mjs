import { describe, expect, it } from "vitest";
import {
  validateLighthouseReport, summarizeLighthouseRuns, validateLighthousePort
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
  it("requires strictly validated unprivileged ports", () => {
    expect(validateLighthousePort(undefined)).toBe(4181);
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
