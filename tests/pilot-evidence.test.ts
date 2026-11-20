import { describe, expect, it } from "vitest";
import {
  PILOT_TASKS, summarizeSyntheticPilotEvidence
} from "./pilot-evidence";

describe("UX-5.1 synthetic pilot evidence rubric", () => {
  it("requires every task to be evidenced before calling the automated journey passed", () => {
    const result = summarizeSyntheticPilotEvidence(PILOT_TASKS);
    expect(result.schemaVersion).toBe(1);
    expect(result.provenance).toBe("playwright-synthetic-api");
    expect(result.automatedAcceptance).toBe("passed");
    expect(result.tasks).toHaveLength(7);
    expect(result.tasks.every(task => task.status === "passed")).toBe(true);
  });

  it("never substitutes E2E success for human usability, screen readers or security clearance", () => {
    const result = summarizeSyntheticPilotEvidence(PILOT_TASKS);
    expect(result.humanUsability).toBe("not_conducted");
    expect(result.manualAssistiveTechnology).toBe("not_conducted");
    expect(result.productionAuthorization).toBe("not_granted");
    expect(JSON.stringify(result)).not.toMatch(/productionReady|userSuccessRate|wcagCertified/);
  });

  it("records incomplete evidence explicitly and does not silently fill tasks", () => {
    const result = summarizeSyntheticPilotEvidence(["scope_opened", "pdf_quarantined"]);
    expect(result.automatedAcceptance).toBe("incomplete");
    expect(result.tasks.filter(task => task.status === "not_evidenced")).toHaveLength(5);
    expect(result.tasks[2]).toEqual({ id: "draft_registered", status: "not_evidenced" });
  });

  it("rejects unknown or duplicate tasks to preserve traceability", () => {
    expect(() => summarizeSyntheticPilotEvidence([
      "scope_opened", "scope_opened"
    ])).toThrow(/duplicad/i);
    expect(() => summarizeSyntheticPilotEvidence([
      "scope_opened", "official_approval" as never
    ])).toThrow(/desconocid/i);
  });

  it("does not embed actor names, identifiers, file names or document contents", () => {
    const report = summarizeSyntheticPilotEvidence(["scope_opened"]);
    expect(Object.keys(report).sort()).toEqual([
      "automatedAcceptance", "humanUsability", "manualAssistiveTechnology",
      "productionAuthorization", "provenance", "schemaVersion", "tasks"
    ].sort());
    expect(report.tasks.map(task => Object.keys(task).sort())).toEqual(
      PILOT_TASKS.map(() => ["id", "status"])
    );
  });
});
