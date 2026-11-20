/**
 * A single validated port contract shared by the loopback demo and its E2E.
 * Reject unexpected input rather than allowing an implicit port fallback.
 */
export function resolveDemoPort(raw = "4176") {
  if (typeof raw !== "string" || !/^[1-9][0-9]{3,4}$/.test(raw)
      || Number(raw) < 1024 || Number(raw) > 65535) {
    throw new Error("FOLIO_DEMO_PORT must be an unprivileged TCP port (1024-65535)");
  }
  return Number(raw);
}
