import { describe, expect, it } from "vitest";
import { validateEvidence } from "./evidence";

const hash = "a".repeat(64);

describe("evidence provenance", () => {
  it("accepts a reproducible document page citation", () => {
    expect(validateEvidence({
      type: "DOCUMENT_PAGE", commissionId: "com_1", documentVersionId: "ver_1",
      page: 3, sha256: hash
    }).type).toBe("DOCUMENT_PAGE");
  });

  it.each([0, -1, 2.4])("rejects invalid page %s", (page) => {
    expect(() => validateEvidence({
      type: "DOCUMENT_PAGE", commissionId: "com_1", documentVersionId: "ver_1",
      page, sha256: hash
    })).toThrow();
  });

  it("rejects broken hashes and missing document versions", () => {
    expect(() => validateEvidence({
      type: "DOCUMENT_PAGE", commissionId: "com_1", documentVersionId: "",
      page: 1, sha256: "abc"
    })).toThrow();
  });

  it("records a search scope for documents not found, without requiring a page", () => {
    expect(validateEvidence({
      type: "SEARCH_SCOPE", commissionId: "com_1", checklistItemId: "check_2",
      batchId: "batch_5", reviewerId: "member_4",
      searchedAt: "2026-11-18T12:00:00.000Z"
    }).type).toBe("SEARCH_SCOPE");
  });

  it("rejects fabricated absence without a reviewer or search date", () => {
    expect(() => validateEvidence({
      type: "SEARCH_SCOPE", commissionId: "com_1", checklistItemId: "check_2",
      batchId: "batch_5", reviewerId: "", searchedAt: "yesterday"
    })).toThrow();
  });

  it("requires source and timestamp for official citations", () => {
    expect(() => validateEvidence({
      type: "OFFICIAL_SOURCE", commissionId: "com_1", source: "OECE",
      sourceRecordId: "123", consultedAt: "", cutOffAt: "2026-12-31"
    })).toThrow();
  });
});
