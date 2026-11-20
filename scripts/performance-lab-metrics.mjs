/**
 * PERF-002: validate browser-observed lab samples. No invented or substituted
 * performance values; a missing paint entry is an error, never a zero.
 */
const FIELDS = ["ttfbMs", "fcpMs", "lcpMs", "cls"];

export function validateLabSample(sample) {
  if (!sample || typeof sample !== "object") {
    throw new Error("Missing Chromium performance sample");
  }
  const measured = {};
  for (const field of FIELDS) {
    const value = sample[field];
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
      throw new Error("Invalid or missing Chromium lab metric: " + field);
    }
    measured[field] = value;
  }
  if (measured.fcpMs === 0 || measured.lcpMs === 0) {
    throw new Error("Missing content paint event in Chromium");
  }
  return measured;
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
}

export function summarizeLabMetrics(samples) {
  if (!Array.isArray(samples) || samples.length < 3) {
    throw new Error("At least three isolated Chromium navigations are required");
  }
  const valid = samples.map(validateLabSample);
  return {
    navigations: valid.length,
    median: Object.fromEntries(FIELDS.map(field =>
      [field, median(valid.map(sample => sample[field]))]
    ))
  };
}
