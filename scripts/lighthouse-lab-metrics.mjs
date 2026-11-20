/**
 * A Lighthouse JSON report is only usable when it was captured from our
 * intended loopback origin, completed without an error and has real metrics.
 */
export function validateLighthousePort(raw = "4181") {
  if (typeof raw !== "string" || !/^[1-9][0-9]{3,4}$/.test(raw)
      || Number(raw) < 1024 || Number(raw) > 65535) {
    throw new Error("FOLIO_LIGHTHOUSE_PORT must be an unprivileged TCP port (1024-65535)");
  }
  return Number(raw);
}

export function validateLighthouseReport(lhr, expectedUrl) {
  if (!lhr || typeof lhr !== "object" || lhr.runtimeError) {
    throw new Error("Lighthouse returned no report or a runtime error");
  }
  if (typeof expectedUrl !== "string"
      || !/^http:\/\/127\.0\.0\.1:[0-9]+\/$/.test(expectedUrl)
      || lhr.requestedUrl !== expectedUrl
      || lhr.finalDisplayedUrl !== expectedUrl) {
    throw new Error("Lighthouse audited an unexpected origin or navigation");
  }
  const rawScore = lhr.categories?.performance?.score;
  if (typeof rawScore !== "number" || !Number.isFinite(rawScore)
      || rawScore < 0 || rawScore > 1) {
    throw new Error("Lighthouse performance score is missing or invalid");
  }
  const field = (name, allowZero = true) => {
    const value = lhr.audits?.[name]?.numericValue;
    if (typeof value !== "number" || !Number.isFinite(value)
        || value < 0 || (!allowZero && value === 0)) {
      throw new Error("Missing or invalid Lighthouse audit: " + name);
    }
    return value;
  };
  return {
    score: Math.round(rawScore * 100),
    fcpMs: field("first-contentful-paint", false),
    lcpMs: field("largest-contentful-paint", false),
    cls: field("cumulative-layout-shift"),
    tbtMs: field("total-blocking-time")
  };
}

function median(numbers) {
  const values = [...numbers].sort((a, b) => a - b);
  const middle = Math.floor(values.length / 2);
  return values.length % 2 ? values[middle]
    : (values[middle - 1] + values[middle]) / 2;
}

export function summarizeLighthouseRuns(lhrs, expectedUrl) {
  if (!Array.isArray(lhrs) || lhrs.length < 3) {
    throw new Error("At least three real Lighthouse runs are required");
  }
  const records = lhrs.map(lhr => validateLighthouseReport(lhr, expectedUrl));
  return {
    runs: records.length,
    median: Object.fromEntries(
      ["score", "fcpMs", "lcpMs", "cls", "tbtMs"].map(
        field => [field, median(records.map(record => record[field]))]
      )
    )
  };
}


/** Detect the exact startup URL of our spawned Vite process, not log chatter.
 * Under CI=true Vite colors even the port inside its URL; strip ANSI SGR.
 */
export function hasOwnVitePreviewUrl(output, expectedUrl) {
  if (typeof output !== "string" || typeof expectedUrl !== "string"
      || !/^http:\/\/127\.0\.0\.1:[0-9]+\/$/.test(expectedUrl)) return false;
  const plain = output.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "");
  return plain.split(/\r?\n/).some(line =>
    /\bLocal:\s+/.test(line) && line.includes(expectedUrl)
  );
}
