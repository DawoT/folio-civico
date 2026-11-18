import { describe, expect, it } from "vitest";
import { createObservationDraft } from "./observations";

const base = {
  commissionId: "com_a", authorSubject: "user_a",
  title: "Monto requiere contraste", description: "Comparar el contrato y su adenda.",
  evidence: [{
    type: "DOCUMENT_PAGE" as const, commissionId: "com_a",
    documentVersionId: "ver_a", page: 7, sha256: "f".repeat(64)
  }]
};

describe("observation drafts", () => {
  it("always creates an unvalidated proposal", () => {
    const proposal = createObservationDraft(base);
    expect(proposal.status).toBe("draft");
    expect(proposal.validatedBy).toBeNull();
    expect(proposal.evidence).toHaveLength(1);
  });

  it("rejects evidence from another commission", () => {
    expect(() => createObservationDraft({
      ...base,
      evidence: [{ ...base.evidence[0]!, commissionId: "com_b" }]
    })).toThrow();
  });

  it("does not create documentary observations without evidence", () => {
    expect(() => createObservationDraft({ ...base, evidence: [] })).toThrow();
  });
});
