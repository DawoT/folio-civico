import {
  collectFinalizedReviews, getCommissionSummary, MAX_FINALIZED_REVIEW_EXPORT, ReviewExportLimitError
} from "@folio/data";
import { isValidReviewExportPayload } from "../../../packages/domain/src/review-export-structure.mjs";

export interface ReviewExportEnv { DB: D1Database; }

export const REVIEW_EXPORT_FORMAT = "folio-civico.review-export.v1";
const MAX_REPORT_BYTES = 8 * 1024 * 1024;

function errorJson(status: number, message: string): Response {
  return Response.json({ error: message }, {
    status, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
  });
}

/**
 * SHA-256 protects byte-level integrity of the embedded payload. It does not
 * authenticate the issuer, attest source documents or constitute a signature.
 */
export async function handleReviewExportRequest(
  request: Request, env: ReviewExportEnv, subject: string, commissionId: string
): Promise<Response> {
  if (request.method !== "GET") return errorJson(405, "Method not allowed");
  if (new URL(request.url).search) return errorJson(400, "Report filters are not supported");
  try {
    const data = await collectFinalizedReviews(env.DB, subject, commissionId);
    if (!data) return errorJson(404, "Not found");

    const payload = {
      schemaVersion: 1,
      kind: "internal_human_review",
      disclaimer: "Insumo de trabajo. No constituye acta oficial, firma digital ni certificación de la Contraloría.",
      generatedAt: new Date().toISOString(),
      commission: data.commission,
      completeness: {
        statuses: ["validated", "dismissed"] as const,
        included: data.records.length, truncated: false,
        maximumPerExport: MAX_FINALIZED_REVIEW_EXPORT
      },
      observations: data.records
    };
    // Reject malformed or missing provenance before hashing and publishing a
    // seemingly intact file. Use the exact offline/browser v1 validator.
    if (!isValidReviewExportPayload(payload)) {
      return errorJson(503, "Report could not be generated");
    }
    // The payload is retained as a string to make offline hash verification
    // independent of JSON whitespace, key order and downstream formatting.
    const payloadJson = JSON.stringify(payload);
    const encoded = new TextEncoder().encode(payloadJson);
    if (encoded.byteLength > MAX_REPORT_BYTES) {
      return errorJson(413, "Report exceeds maximum size; no partial file was generated");
    }
    const sha256 = Array.from(
      new Uint8Array(await crypto.subtle.digest("SHA-256", encoded)),
      byte => byte.toString(16).padStart(2, "0")
    ).join("");
    // WebCrypto is asynchronous. Membership may be revoked while hashing,
    // even if the collector already fenced its D1 rows read. Revalidate
    // immediately before returning a download, with no subsequent awaits.
    if (!await getCommissionSummary(env.DB, subject, commissionId)) {
      return errorJson(404, "Not found");
    }
    const body = JSON.stringify({ format: REVIEW_EXPORT_FORMAT, sha256, payload: payloadJson });
    return new Response(body, {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Disposition": `attachment; filename="folio-civico-${commissionId}-revision-interna.json"`,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Report-SHA256": sha256
      }
    });
  } catch (error) {
    if (error instanceof ReviewExportLimitError) {
      return errorJson(409, "The complete report exceeds 500 finalized observations; export is blocked rather than truncated");
    }
    return errorJson(503, "Report could not be generated");
  }
}
