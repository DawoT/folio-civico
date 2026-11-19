import { getObservationForMember } from "@folio/data";

export interface ObservationDetailEnv { DB: D1Database; }

function json(body: unknown, status: number): Response {
  return Response.json(body, {
    status, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
  });
}

/** Only called after Access JWT authentication. Uses commission-scoped active membership. */
export async function handleObservationDetailRequest(
  request: Request, env: ObservationDetailEnv, subject: string,
  commissionId: string, observationId: string
): Promise<Response> {
  if (request.method !== "GET") return json({error: "Method not allowed"}, 405);
  try {
    const record = await getObservationForMember(env.DB, subject, commissionId, observationId);
    if (!record) return json({error: "Not found"}, 404);
    // Explicit allowlist: never expose internal request keys or database metadata.
    return json({
      id: record.id, commissionId: record.commissionId,
      authorSubject: record.authorSubject,
      title: record.title, description: record.description,
      status: record.status, validatedBy: record.validatedBy,
      createdAt: record.createdAt, evidence: record.evidence,
      reviewedBy: record.reviewedBy, reviewedAt: record.reviewedAt,
      reviewNote: record.reviewNote
    }, 200);
  } catch {
    return json({error: "Request could not be completed"}, 503);
  }
}
