import { assertMemberPermission } from "@folio/domain";
import {
  getBatchAccess, getExistingUpload, listBatchDocuments, persistDocumentUpload,
  type ExistingUpload
} from "@folio/data";
import { PdfValidationError, readPdfUpload } from "@folio/documents";

export interface DocumentRouteEnv {
  DB: D1Database;
  DOCUMENTS?: R2Bucket;
}

function json(body: unknown, status: number): Response {
  return Response.json(body, {
    status, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
  });
}

function documentResult(
  documentId: string, versionId: string, sha256: string,
  processingStatus: ExistingUpload["processingStatus"], repeated: boolean
): Response {
  return json({
    documentId, versionId, sha256, ingestStatus: "quarantined",
    processingStatus, repeated
  }, repeated ? 200 : 201);
}

/**
 * The first permission check can become stale across an awaited D1/R2 read.
 * Revalidate the same commission+batch binding after the data is available
 * and before disclosing it or acknowledging an idempotent write replay.
 */
async function finalAccessFence(
  env: DocumentRouteEnv, subject: string, commissionId: string,
  batchId: string, mode: "read" | "draft"
): Promise<Response | null> {
  const current = await getBatchAccess(env.DB, subject, commissionId, batchId);
  if (!current) return json({ error: "Not found" }, 404);
  if (mode === "draft" && current.commissionStatus !== "active") {
    return json({ error: "Commission is closed" }, 409);
  }
  try {
    assertMemberPermission({
      commissionId, subject, role: current.role, active: true
    }, subject, commissionId, mode);
  } catch {
    return json({ error: "Forbidden" }, 403);
  }
  return null;
}

/**
 * Internal route: subject is from a verified Access JWT, NEVER a request parameter.
 * The repository rechecks membership on every database operation.
 */
export async function handleDocumentRequest(
  request: Request, env: DocumentRouteEnv, subject: string,
  commissionId: string, batchId: string
): Promise<Response> {
  if (!["GET", "POST"].includes(request.method)) {
    return json({ error: "Method not allowed" }, 405);
  }
  try {
    const access = await getBatchAccess(env.DB, subject, commissionId, batchId);
    if (!access) return json({ error: "Not found" }, 404);
    assertMemberPermission({
      commissionId, subject, role: access.role, active: true
    }, subject, commissionId, request.method === "GET" ? "read" : "draft");

    if (request.method === "GET") {
      const documents = await listBatchDocuments(env.DB, subject, commissionId, batchId);
      const denied = await finalAccessFence(env, subject, commissionId, batchId, "read");
      return denied ?? json(documents, 200);
    }

    if (access.commissionStatus !== "active") return json({ error: "Commission is closed" }, 409);
    // Same-origin only: a browser authenticated by Access must not be able to upload via CSRF.
    const origin = request.headers.get("Origin");
    if (origin && origin !== new URL(request.url).origin) return json({ error: "Forbidden" }, 403);
    if (!env.DOCUMENTS) return json({ error: "Document storage is not configured" }, 503);

    const pdf = await readPdfUpload(request);
    const existing = await getExistingUpload(env.DB, subject, commissionId, pdf.idempotencyKey);
    if (existing) {
      const denied = await finalAccessFence(env, subject, commissionId, batchId, "draft");
      if (denied) return denied;
      if (existing.sha256 !== pdf.sha256 || existing.batchId !== batchId) {
        return json({ error: "Idempotency key already belongs to another upload" }, 409);
      }
      return documentResult(existing.documentId, existing.versionId, existing.sha256,
        existing.processingStatus, true);
    }

    const documentId = crypto.randomUUID();
    const versionId = crypto.randomUUID();
    // Randomized object key: no filenames, entity names or identifiers in R2 paths.
    const r2Key = `quarantine/${crypto.randomUUID()}.pdf`;
    try {
      const stored = await env.DOCUMENTS.put(r2Key, pdf.bytes, {
        httpMetadata: { contentType: "application/pdf", contentDisposition: "attachment" },
        customMetadata: { sha256: pdf.sha256 }
      });
      if (!stored) throw new Error("R2 did not acknowledge the upload");
    } catch {
      return json({ error: "Unable to store document" }, 503);
    }

    try {
      await persistDocumentUpload(env.DB, {
        commissionId, batchId, subject, documentId, versionId,
        sha256: pdf.sha256, r2Key, filename: pdf.filename, idempotencyKey: pdf.idempotencyKey
      });
    } catch {
      // Resolve a concurrent retry before declaring failure; only the second object is deleted.
      let concurrent: Awaited<ReturnType<typeof getExistingUpload>> = null;
      try {
        concurrent = await getExistingUpload(env.DB, subject, commissionId, pdf.idempotencyKey);
      } catch {
        // Database unavailable; object cleanup below is still attempted.
      }

      try {
        await env.DOCUMENTS.delete(r2Key);
      } catch {
        // Quarantine objects may require a retention/lifecycle sweeper after an R2 outage.
      }
      if (concurrent) {
        const denied = await finalAccessFence(env, subject, commissionId, batchId, "draft");
        if (denied) return denied;
        if (concurrent.sha256 === pdf.sha256 && concurrent.batchId === batchId) {
          return documentResult(concurrent.documentId, concurrent.versionId, concurrent.sha256,
            concurrent.processingStatus, true);
        }
        return json({ error: "Idempotency key already belongs to another upload" }, 409);
      }
      return json({ error: "Unable to register document" }, 503);
    }
    // D1 has committed the document, version, audit and outbox. Never run
    // the failed-insert R2 cleanup if this final permission query fails:
    // deleting the object here would corrupt an already-durable upload.
    const denied = await finalAccessFence(env, subject, commissionId, batchId, "draft");
    return denied ?? documentResult(documentId, versionId, pdf.sha256, "pending", false);
  } catch (error) {
    if (error instanceof PdfValidationError) return json({ error: error.message }, error.status);
    if (error instanceof Error && error.message === "Forbidden") {
      return json({ error: "Forbidden" }, 403);
    }
    return json({ error: "Request could not be completed" }, 503);
  }
}
