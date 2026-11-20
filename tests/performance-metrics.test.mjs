import { describe, expect, it } from "vitest";
import { summarizeLabMetrics, validateLabSample } from "../scripts/performance-lab-metrics.mjs";

describe("PERF-002 synthetic Chromium lab metrics", () => {
  it("rejects missing paint entries and invalid measurements instead of treating them as zero", () => {
    const valid = { ttfbMs: 13, fcpMs: 55, lcpMs: 90, cls: 0 };
    expect(validateLabSample(valid)).toEqual(valid);
    for (const bad of [
      { ...valid, fcpMs: null },
      { ...valid, lcpMs: undefined },
      { ...valid, cls: -0.01 },
      { ...valid, ttfbMs: NaN },
      { ...valid, fcpMs: Number.POSITIVE_INFINITY },
      { ...valid, lcpMs: "88" }
    ]) expect(() => validateLabSample(bad)).toThrow();
  });

  it("requires at least three measured navigations for a report", () => {
    const sample = { ttfbMs: 14, fcpMs: 58, lcpMs: 89, cls: 0 };
    expect(() => summarizeLabMetrics([sample, sample])).toThrow(/three/i);
  });

  it("calculates medians from samples, preserving zero as an actual CLS measurement", () => {
    const report = summarizeLabMetrics([
      { ttfbMs: 3, fcpMs: 60, lcpMs: 120, cls: 0 },
      { ttfbMs: 8, fcpMs: 30, lcpMs: 110, cls: 0.04 },
      { ttfbMs: 5, fcpMs: 40, lcpMs: 140, cls: 0.02 }
    ]);
    expect(report).toEqual({
      navigations: 3,
      median: { ttfbMs: 5, fcpMs: 40, lcpMs: 120, cls: 0.02 }
    });
  });
});
