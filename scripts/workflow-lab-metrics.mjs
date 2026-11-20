/**
 * PERF-004: synthetic authorized-role workflow contract and timing aggregation.
 * Wall clock stages include Playwright automation, local API fixture and UI rendering.
 * They are NOT INP, real user timing or authenticated Worker latency.
 */
const STEPS = ["discoveryMs", "openScopeMs", "historyPageMs", "detailOpenMs"];

export function validateWorkflowSample(sample) {
  if (sample === null || typeof sample !== "object") {
    throw new Error("Missing complete synthetic workflow sample");
  }
  if (sample.firstPageItems !== 25 || sample.totalItems !== 40
    || sample.sawSecondPage !== true || sample.sawDocument !== true
    || sample.sawChecklist !== true || sample.productionAssets !== true
    || sample.unexpectedRequests !== 0 || sample.mutations !== 0) {
    throw new Error("Incomplete, unauthorized or non-production workflow evidence");
  }
  const durations = {};
  for (const key of STEPS) {
    const value = sample[key];
    if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
      throw new Error("Invalid or missing workflow stage: " + key);
    }
    durations[key] = value;
  }
  return durations;
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

export function summarizeWorkflowLab(samples) {
  if (!Array.isArray(samples) || samples.length < 3) {
    throw new Error("At least three isolated workflows are required");
  }
  const measured = samples.map(validateWorkflowSample);
  return {
    workflows: measured.length,
    fixture: { firstPageItems: 25, totalItems: 40 },
    median: Object.fromEntries(
      STEPS.map(key => [key, median(measured.map(sample => sample[key]))])
    )
  };
}
