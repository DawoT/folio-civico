import { describe, it, expect } from "vitest";
import { validateWorkflowSample, summarizeWorkflowLab } from "../scripts/workflow-lab-metrics.mjs";

const valid = {
  discoveryMs: 23.4,
  openScopeMs: 41.7,
  historyPageMs: 57.3,
  detailOpenMs: 20.1,
  firstPageItems: 25,
  totalItems: 40,
  sawSecondPage: true,
  sawDocument: true,
  sawChecklist: true,
  productionAssets: true,
  unexpectedRequests: 0,
  mutations: 0
};
describe("PERF-004 authorized synthetic workflow timings", () => {
  it("rejects missing or invented timings, invalid state and unsafe requests", () => {
    expect(validateWorkflowSample(valid)).toEqual({
      discoveryMs: 23.4, openScopeMs: 41.7, historyPageMs: 57.3, detailOpenMs: 20.1
    });
    for (const bad of [
      { ...valid, discoveryMs: null },
      { ...valid, openScopeMs: 0 },
      { ...valid, historyPageMs: -1 },
      { ...valid, detailOpenMs: Number.POSITIVE_INFINITY },
      { ...valid, firstPageItems: 24 },
      { ...valid, totalItems: 25 },
      { ...valid, sawSecondPage: false },
      { ...valid, sawDocument: false },
      { ...valid, sawChecklist: false },
      { ...valid, productionAssets: false },
      { ...valid, unexpectedRequests: 1 },
      { ...valid, mutations: 1 }
    ]) expect(() => validateWorkflowSample(bad)).toThrow();
  });
  it("requires three full isolated workflows", () => {
    expect(() => summarizeWorkflowLab([valid, valid])).toThrow(/three/i);
  });
  it("reports stage medians, not fake server or INP latency", () => {
    const out = summarizeWorkflowLab([
      valid,
      { ...valid, discoveryMs: 11, openScopeMs: 21, historyPageMs: 43, detailOpenMs: 14 },
      { ...valid, discoveryMs: 31, openScopeMs: 66, historyPageMs: 75, detailOpenMs: 25 }
    ]);
    expect(out).toEqual({
      workflows: 3,
      fixture: { firstPageItems: 25, totalItems: 40 },
      median: { discoveryMs: 23.4, openScopeMs: 41.7, historyPageMs: 57.3, detailOpenMs: 20.1 }
    });
  });
});
