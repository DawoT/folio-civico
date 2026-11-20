/** Structural format-v1 validation; does not verify a digest or author identity. */
export interface ValidReviewExportPayload {
  schemaVersion: 1;
  kind: "internal_human_review";
  commission: { id: string; name: string; status: "active" | "closed" };
  completeness: { included: number; truncated: false; maximumPerExport: 500 };
  observations: Array<{ id: string; status: "validated" | "dismissed" }>;
}
export function isValidReviewExportPayload(payload: unknown): payload is ValidReviewExportPayload;
