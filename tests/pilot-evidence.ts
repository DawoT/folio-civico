/**
 * Automated pilot acceptance is not a human usability study, a WCAG
 * certification, or an inspector/production release approval.
 * This allowlist ensures evidence attachments cannot accidentally include
 * actor subjects, filenames, hashes, or document text.
 */
export const PILOT_TASKS = [
  "scope_opened",
  "pdf_quarantined",
  "draft_registered",
  "submitted_for_review",
  "independent_decision",
  "observer_read_only",
  "sha256_export_verified"
] as const;

export type PilotTaskId = typeof PILOT_TASKS[number];

export interface SyntheticPilotEvidence {
  schemaVersion: 1;
  provenance: "playwright-synthetic-api";
  automatedAcceptance: "passed" | "incomplete";
  tasks: Array<{ id: PilotTaskId; status: "passed" | "not_evidenced" }>;
  humanUsability: "not_conducted";
  manualAssistiveTechnology: "not_conducted";
  productionAuthorization: "not_granted";
}

export function summarizeSyntheticPilotEvidence(
  completed: readonly PilotTaskId[]
): SyntheticPilotEvidence {
  const known = new Set<string>(PILOT_TASKS);
  const seen = new Set<string>();
  for (const task of completed) {
    if (!known.has(task)) throw new Error("Tarea de piloto desconocida.");
    if (seen.has(task)) throw new Error("Evidencia de tarea duplicada.");
    seen.add(task);
  }

  return {
    schemaVersion: 1,
    provenance: "playwright-synthetic-api",
    automatedAcceptance: seen.size === PILOT_TASKS.length ? "passed" : "incomplete",
    tasks: PILOT_TASKS.map(id => ({
      id, status: seen.has(id) ? "passed" : "not_evidenced"
    })),
    humanUsability: "not_conducted",
    manualAssistiveTechnology: "not_conducted",
    productionAuthorization: "not_granted"
  };
}
