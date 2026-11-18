export interface DocumentPageEvidence {
  type: "DOCUMENT_PAGE";
  commissionId: string;
  documentVersionId: string;
  page: number;
  sha256: string;
}
export interface SearchScopeEvidence {
  type: "SEARCH_SCOPE";
  commissionId: string;
  checklistItemId: string;
  batchId: string;
  reviewerId: string;
  searchedAt: string;
}
export interface OfficialSourceEvidence {
  type: "OFFICIAL_SOURCE";
  commissionId: string;
  source: string;
  sourceRecordId: string;
  consultedAt: string;
  cutOffAt: string;
}

export type Evidence = DocumentPageEvidence | SearchScopeEvidence | OfficialSourceEvidence;

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Evidence must be a structured object");
  }
  return value as Record<string, unknown>;
}

function nonempty(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`Invalid ${field}`);
  }
  return value.trim();
}

function timestamp(value: unknown, field: string): string {
  const result = nonempty(value, field);
  const parsed = new Date(result);
  if (!Number.isFinite(parsed.valueOf()) || parsed.toISOString() !== result) {
    throw new Error(`Invalid ${field}`);
  }
  return result;
}

function dateOnly(value: unknown, field: string): string {
  const result = nonempty(value, field);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(result)
    || new Date(`${result}T00:00:00.000Z`).toISOString().slice(0, 10) !== result) {
    throw new Error(`Invalid ${field}`);
  }
  return result;
}

/** Verify provenance, never infer a reference from AI-produced text. */
export function validateEvidence(input: unknown): Evidence {
  const value = object(input);
  const commissionId = nonempty(value.commissionId, "commissionId");

  switch (value.type) {
    case "DOCUMENT_PAGE": {
      const documentVersionId = nonempty(value.documentVersionId, "documentVersionId");
      if (!Number.isSafeInteger(value.page) || (value.page as number) < 1) {
        throw new Error("Document evidence requires a positive page");
      }
      const sha256 = nonempty(value.sha256, "sha256").toLowerCase();
      if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error("Invalid SHA-256");
      return { type: "DOCUMENT_PAGE", commissionId, documentVersionId, page: value.page as number, sha256 };
    }
    case "SEARCH_SCOPE":
      return {
        type: "SEARCH_SCOPE", commissionId,
        checklistItemId: nonempty(value.checklistItemId, "checklistItemId"),
        batchId: nonempty(value.batchId, "batchId"),
        reviewerId: nonempty(value.reviewerId, "reviewerId"),
        searchedAt: timestamp(value.searchedAt, "searchedAt")
      };
    case "OFFICIAL_SOURCE":
      return {
        type: "OFFICIAL_SOURCE", commissionId,
        source: nonempty(value.source, "source"),
        sourceRecordId: nonempty(value.sourceRecordId, "sourceRecordId"),
        consultedAt: timestamp(value.consultedAt, "consultedAt"),
        cutOffAt: dateOnly(value.cutOffAt, "cutOffAt")
      };
    default: throw new Error("Unrecognized evidence type");
  }
}
