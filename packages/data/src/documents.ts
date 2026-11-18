import type { MemberRole } from "@folio/domain";

export interface BatchAccess {
  role: MemberRole;
  commissionStatus: "active" | "closed";
}
export interface BatchDocument {
  id: string;
  filename: string;
  versionId: string;
  sha256: string;
  extractionStatus: "pending" | "processing" | "ready" | "needs_review" | "failed";
  pageCount: number | null;
  createdAt: string;
}
export interface ExistingUpload {
  documentId: string;
  versionId: string;
  batchId: string;
  sha256: string;
}
export interface DocumentUploadInput {
  commissionId: string;
  batchId: string;
  subject: string;
  documentId: string;
  versionId: string;
  sha256: string;
  r2Key: string;
  filename: string;
  idempotencyKey: string;
}

export async function getBatchAccess(
  db: D1Database, subject: string, commissionId: string, batchId: string
): Promise<BatchAccess | null> {
  if (!subject || !commissionId || !batchId) return null;
  return db.prepare(`
    SELECT m.role, c.status AS commissionStatus
    FROM document_batches b
      JOIN commissions c ON c.id = b.commission_id
      JOIN commission_members m ON m.commission_id = b.commission_id
    WHERE b.id = ? AND b.commission_id = ? AND m.subject = ? AND m.active = 1
    LIMIT 1
  `).bind(batchId, commissionId, subject).first<BatchAccess>();
}

export async function listBatchDocuments(
  db: D1Database, subject: string, commissionId: string, batchId: string
): Promise<BatchDocument[]> {
  if (!subject || !commissionId || !batchId) return [];
  const rows = await db.prepare(`
    SELECT d.id, d.filename, v.id AS versionId, v.sha256,
      v.extraction_status AS extractionStatus, v.page_count AS pageCount,
      d.created_at AS createdAt
    FROM documents d
    JOIN document_batches b ON b.id = d.batch_id AND b.commission_id = d.commission_id
    JOIN commission_members m ON m.commission_id = d.commission_id
    JOIN document_versions v ON v.document_id = d.id
    WHERE d.commission_id = ? AND b.id = ? AND m.subject = ? AND m.active = 1
      AND v.version_number = (SELECT MAX(v2.version_number) FROM document_versions v2 WHERE v2.document_id = d.id)
    ORDER BY d.created_at DESC, d.id DESC LIMIT 100
  `).bind(commissionId, batchId, subject).all<BatchDocument>();
  return rows.results;
}

export async function getExistingUpload(
  db: D1Database, subject: string, commissionId: string, idempotencyKey: string
): Promise<ExistingUpload | null> {
  if (!subject || !commissionId || !idempotencyKey) return null;
  return db.prepare(`
    SELECT d.id AS documentId, v.id AS versionId, d.batch_id AS batchId, v.sha256
    FROM documents d
    JOIN commission_members m ON m.commission_id = d.commission_id
    JOIN document_versions v ON v.document_id = d.id AND v.version_number = 1
    WHERE d.commission_id = ? AND d.upload_request_key = ?
      AND m.subject = ? AND m.active = 1
    LIMIT 1
  `).bind(commissionId, idempotencyKey, subject).first<ExistingUpload>();
}

export async function persistDocumentUpload(db: D1Database, input: DocumentUploadInput): Promise<void> {
  const statements = [
    db.prepare(`
      INSERT INTO documents(id, commission_id, batch_id, filename, upload_request_key)
      SELECT ?, b.commission_id, b.id, ?, ?
      FROM document_batches b
      JOIN commissions c ON c.id = b.commission_id
      JOIN commission_members m ON m.commission_id = b.commission_id
      WHERE b.id = ? AND b.commission_id = ? AND c.status = 'active'
        AND m.subject = ? AND m.active = 1
        AND m.role IN ('president', 'member', 'advisor')
    `).bind(input.documentId, input.filename, input.idempotencyKey,
      input.batchId, input.commissionId, input.subject),
    db.prepare(`
      INSERT INTO document_versions(id, document_id, version_number, sha256, r2_object_key)
      SELECT ?, d.id, 1, ?, ?
      FROM documents d
      WHERE d.id = ? AND d.commission_id = ? AND d.batch_id = ?
    `).bind(input.versionId, input.sha256, input.r2Key,
      input.documentId, input.commissionId, input.batchId),
    db.prepare(`
      INSERT INTO audit_events(id, commission_id, actor_subject, action, resource_type, resource_id, metadata_json)
      SELECT ?, d.commission_id, ?, 'document.uploaded_to_quarantine', 'document', d.id, NULL
      FROM documents d
      WHERE d.id = ? AND d.commission_id = ?
    `).bind(crypto.randomUUID(), input.subject, input.documentId, input.commissionId)
  ];

  // D1.batch executes atomically; a failed statement rolls the transaction back.
  const results = await db.batch(statements);
  if (!results[0]?.success || results[0]?.meta.changes !== 1
    || !results[1]?.success || results[1]?.meta.changes !== 1
    || !results[2]?.success || results[2]?.meta.changes !== 1) {
    throw new Error("Unauthorized or inconsistent document intake");
  }
}
