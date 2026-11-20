import { describe, expect, it } from "vitest";
import { isValidReviewExportPayload } from "../packages/domain/src/review-export-structure.mjs";

const valid = {
  schemaVersion: 1,
  kind: "internal_human_review",
  disclaimer: "Solo trabajo interno",
  generatedAt: "2026-11-20T12:00:00.000Z",
  commission: { id: "c_a", name: "Comisión sintética", status: "active" },
  completeness: {
    statuses: ["validated", "dismissed"], included: 1,
    truncated: false, maximumPerExport: 500
  },
  observations: [{
    id: "obs_a", authorSubject: "author", title: "Registro sintético",
    description: "Búsqueda del lote", status: "validated",
    createdAt: "2026-11-20T11:00:00.000Z",
    validatedBy: "reviewer", reviewedBy: "reviewer",
    reviewedAt: "2026-11-20T11:30:00.000Z",
    reviewNote: "Revisé personalmente la evidencia",
    evidence: [{
      type: "SEARCH_SCOPE", commissionId: "c_a", checklistItemId: "item_a",
      batchId: "batch_a", reviewerId: "author",
      searchedAt: "2026-11-20T11:00:00.000Z"
    }]
  }]
};
describe("review-export v1 must never accept provenance-free finalized decisions", () => {
  it("preserves a structurally valid fictional review", () => {
    expect(isValidReviewExportPayload(valid)).toBe(true);
  });
  it("rejects a finalized review with no evidence instead of vacuously passing every()", () => {
    const payload = structuredClone(valid);
    payload.observations[0].evidence = [];
    expect(isValidReviewExportPayload(payload)).toBe(false);
  });
  it("rejects a finalized review with an unrecognized evidence type", () => {
    const payload = structuredClone(valid);
    payload.observations[0].evidence[0].type = "UNVERIFIED";
    expect(isValidReviewExportPayload(payload)).toBe(false);
  });
});
