import { createObservationDraft, type Evidence, type ObservationDraftInput } from "@folio/domain";
import { getCommissionSummary } from "./commissions";

export interface ChecklistRow {
  id: string;
  area: "works" | "procurement";
  expectedDocument: string;
  status: "pending" | "located" | "not_located" | "observed";
  reviewedBy: string | null;
  reviewedAt: string | null;
}

export interface SavedObservation {
  id: string;
  commissionId: string;
  authorSubject: string;
  title: string;
  description: string;
  status: "draft" | "in_review" | "validated" | "dismissed";
  validatedBy: string | null;
  createdAt: string;
  evidence: Evidence[];
  canSubmit?: boolean;
  canReview?: boolean;
  reviewedBy?: string | null;
  reviewedAt?: string | null;
  reviewNote?: string | null;
}

export class ReviewAccessError extends Error {}
export class ReviewEvidenceError extends Error {}

function validText(value: string, limit: number): boolean {
  return value.trim().length > 0 && value.length <= limit;
}

export async function listChecklist(db: D1Database, subject: string, commissionId: string): Promise<ChecklistRow[]> {
  if (!subject || !commissionId) throw new ReviewAccessError("Missing identity");
  const result = await db.prepare(`
    SELECT i.id, i.area, i.expected_document AS expectedDocument, i.status,
      i.reviewed_by AS reviewedBy, i.reviewed_at AS reviewedAt
    FROM checklist_items i
    JOIN commission_members m ON m.commission_id = i.commission_id
    WHERE i.commission_id = ? AND m.subject = ? AND m.active = 1
    ORDER BY i.area, i.expected_document, i.id LIMIT 100
  `).bind(commissionId, subject).all<ChecklistRow>();
  return result.results;
}

type ObservationRow = Omit<SavedObservation, "evidence"> & {
  evidenceJson: string | null; submitFlag: number; reviewFlag: number;
};

export async function listObservationDrafts(
  db: D1Database, subject: string, commissionId: string
): Promise<SavedObservation[]> {
  if (!subject || !commissionId) throw new ReviewAccessError("Missing identity");
  const result = await db.prepare(`
    SELECT o.id, o.commission_id AS commissionId, o.author_subject AS authorSubject,
      o.title, o.description, o.status, o.validated_by AS validatedBy,
      o.created_at AS createdAt, o.reviewed_by AS reviewedBy,
      o.reviewed_at AS reviewedAt, o.review_note AS reviewNote,
      CASE WHEN o.status='draft' AND o.author_subject=m.subject
        AND m.role IN ('president','member','advisor') AND c.status='active'
        THEN 1 ELSE 0 END AS submitFlag,
      CASE WHEN o.status='in_review' AND o.author_subject<>m.subject
        AND m.role IN ('president','member') AND c.status='active'
        THEN 1 ELSE 0 END AS reviewFlag,
      e.reference_json AS evidenceJson
    FROM (SELECT id FROM observations WHERE commission_id = ?
      ORDER BY created_at DESC, id DESC LIMIT 50) pick
    JOIN observations o ON o.id = pick.id
    JOIN commission_members m ON m.commission_id = o.commission_id
    JOIN commissions c ON c.id = o.commission_id
    LEFT JOIN observation_evidence e ON e.observation_id = o.id
    WHERE o.commission_id = ? AND m.subject = ? AND m.active = 1
    ORDER BY o.created_at DESC, o.id DESC, e.created_at ASC, e.id ASC
  `).bind(commissionId, commissionId, subject).all<ObservationRow>();

  const grouped = new Map<string, SavedObservation>();
  for (const item of result.results) {
    let record = grouped.get(item.id);
    if (!record) {
      record = {
        id: item.id, commissionId: item.commissionId, authorSubject: item.authorSubject,
        title: item.title, description: item.description, status: item.status,
        validatedBy: item.validatedBy, createdAt: item.createdAt,
        reviewedBy: item.reviewedBy ?? null, reviewedAt:item.reviewedAt ?? null,
        reviewNote:item.reviewNote ?? null,
        canSubmit:item.submitFlag===1,canReview:item.reviewFlag===1,evidence: []
      };
      grouped.set(item.id, record);
    }
    if (item.evidenceJson) record.evidence.push(JSON.parse(item.evidenceJson) as Evidence);
  }
  return Array.from(grouped.values());
}

async function assertEvidenceReady(
  db: D1Database, evidence: Evidence, commissionId: string, authorSubject: string
): Promise<void> {
  if (evidence.commissionId !== commissionId) throw new ReviewEvidenceError("Evidence commission mismatch");
  if (evidence.type === "OFFICIAL_SOURCE") {
    throw new ReviewEvidenceError("Official source snapshots are not enabled");
  }
  if (evidence.type === "SEARCH_SCOPE") {
    if (evidence.reviewerId !== authorSubject) throw new ReviewEvidenceError("Reviewer must be the authenticated author");
    const result = await db.prepare(`
      SELECT 1 AS verified FROM checklist_items i
      JOIN document_batches b ON b.commission_id = i.commission_id
      WHERE i.id = ? AND b.id = ? AND i.commission_id = ?
        AND i.status IN ('pending','not_located')
      LIMIT 1
    `).bind(evidence.checklistItemId, evidence.batchId, commissionId).first();
    if (!result) throw new ReviewEvidenceError("Checklist or search batch not in commission");
    return;
  }

  const result = await db.prepare(`
    SELECT 1 AS verified FROM document_versions v
    JOIN documents d ON d.id = v.document_id
    JOIN document_pages p ON p.document_version_id = v.id
    WHERE v.id = ? AND d.commission_id = ? AND v.sha256 = ?
      AND v.extraction_status = 'ready' AND EXISTS (
        SELECT 1 FROM document_processing_reports r WHERE r.document_version_id=v.id
          AND r.source_sha256=v.sha256 AND r.page_count=v.page_count
      )
      AND p.page = ? AND p.extraction_status = 'ready'
      AND v.page_count >= p.page
    LIMIT 1
  `).bind(evidence.documentVersionId, commissionId, evidence.sha256, evidence.page).first();
  if (!result) throw new ReviewEvidenceError("Page evidence not verified and ready");
}

export async function persistDraftObservation(
  db: D1Database,
  input: ObservationDraftInput,
  idempotency?: { key: string; payloadHash: string }
): Promise<SavedObservation> {
  const draft = createObservationDraft(input);
  if (!validText(draft.title, 160) || !validText(draft.description, 4000)
    || draft.evidence.length > 5) {
    throw new ReviewEvidenceError("Observation exceeds size limits");
  }

  const commission = await getCommissionSummary(db, draft.authorSubject, draft.commissionId);
  if (!commission || commission.status !== "active"
    || commission.role === "observer") {
    throw new ReviewAccessError("No permission to submit observation");
  }
  for (const item of draft.evidence) {
    await assertEvidenceReady(db, item, draft.commissionId, draft.authorSubject);
  }

  const id = crypto.randomUUID();
  const statements = [
    db.prepare(`
      INSERT INTO observations(id,commission_id,author_subject,title,description,status,draft_request_key,draft_payload_sha256)
      SELECT ?,c.id,m.subject,?,?,'draft',?,?
      FROM commissions c JOIN commission_members m ON m.commission_id = c.id
      WHERE c.id = ? AND c.status = 'active'
        AND m.subject = ? AND m.active = 1
        AND m.role IN ('president','member','advisor')
    `).bind(id, draft.title, draft.description, idempotency?.key ?? null,
      idempotency?.payloadHash ?? null, draft.commissionId, draft.authorSubject),
    ...draft.evidence.map((item) =>
      db.prepare(`
        INSERT INTO observation_evidence(id,observation_id,type,reference_json)
        VALUES(?,?,?,?)
      `).bind(crypto.randomUUID(), id, item.type, JSON.stringify(item))),
    db.prepare(`
      INSERT INTO audit_events(id,commission_id,actor_subject,action,resource_type,resource_id,metadata_json)
      SELECT ?,o.commission_id,o.author_subject,'observation.draft_created','observation',o.id,NULL
      FROM observations o WHERE o.id = ? AND o.commission_id = ?
    `).bind(crypto.randomUUID(), id, draft.commissionId)
  ];

  // D1.batch is transactional; triggers double-check evidence at the write boundary.
  const result = await db.batch(statements);
  if (result.some((item) => !item.success || item.meta.changes !== 1)) {
    throw new ReviewEvidenceError("Review write was not permitted");
  }
  return {
    id, commissionId: draft.commissionId, authorSubject: draft.authorSubject,
    title: draft.title, description: draft.description, status: "draft",
    validatedBy: null, createdAt: new Date().toISOString(), evidence: draft.evidence
  };
}

/** Only the verified author may replay this key. Never return another user's draft. */
export async function findIdempotentDraft(
  db: D1Database, subject: string, commissionId: string, key: string
): Promise<{payloadHash: string; observation: SavedObservation} | null> {
  if (!subject || !commissionId || !key) return null;
  const row = await db.prepare(`
    SELECT o.id,o.commission_id AS commissionId,o.author_subject AS authorSubject,
      o.title,o.description,o.status,o.validated_by AS validatedBy,
      o.created_at AS createdAt,o.draft_payload_sha256 AS payloadHash
    FROM observations o
    JOIN commission_members m ON m.commission_id=o.commission_id
    WHERE o.commission_id=? AND o.author_subject=?
      AND o.draft_request_key=? AND m.subject=? AND m.active=1
    LIMIT 1
  `).bind(commissionId,subject,key,subject).first<
    Omit<SavedObservation,"evidence"> & {payloadHash:string}
  >();
  if (!row) return null;
  const evidenceRows = await db.prepare(`
    SELECT reference_json AS referenceJson FROM observation_evidence
    WHERE observation_id=? ORDER BY created_at,id
  `).bind(row.id).all<{referenceJson:string}>();
  const {payloadHash,...base}=row;
  return {
    payloadHash,
    observation:{...base,evidence:evidenceRows.results.map(v=>JSON.parse(v.referenceJson) as Evidence)}
  };
}

export interface ReviewMetadata {
  submittedBy: string | null;
  submittedAt: string | null;
  submitRequestKey: string | null;
  reviewedBy: string | null;
  reviewedAt: string | null;
  reviewNote: string | null;
  reviewRequestKey: string | null;
}

export async function getObservationForMember(
  db: D1Database, subject: string, commissionId: string, observationId: string
): Promise<(SavedObservation & ReviewMetadata) | null> {
  if (!subject || !commissionId || !observationId) return null;
  const row=await db.prepare(`
    SELECT o.id,o.commission_id AS commissionId,o.author_subject AS authorSubject,
      o.title,o.description,o.status,o.validated_by AS validatedBy,
      o.created_at AS createdAt,o.submitted_by AS submittedBy,
      o.submitted_at AS submittedAt,o.submit_request_key AS submitRequestKey,
      o.reviewed_by AS reviewedBy,o.reviewed_at AS reviewedAt,
      o.review_note AS reviewNote,o.review_request_key AS reviewRequestKey
    FROM observations o JOIN commission_members m ON m.commission_id=o.commission_id
    WHERE o.id=? AND o.commission_id=? AND m.subject=? AND m.active=1
  `).bind(observationId,commissionId,subject).first<Omit<SavedObservation,"evidence"> & ReviewMetadata>();
  if (!row) return null;
  const evidenceRows=await db.prepare(`
    SELECT reference_json AS referenceJson FROM observation_evidence
    WHERE observation_id=? ORDER BY created_at,id
  `).bind(row.id).all<{referenceJson:string}>();
  return {...row,evidence:evidenceRows.results.map(v=>JSON.parse(v.referenceJson) as Evidence)};
}
