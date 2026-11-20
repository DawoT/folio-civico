import type { Evidence } from "@folio/domain";
import { getCommissionSummary } from "./commissions";

export const MAX_FINALIZED_REVIEW_EXPORT = 500;

export class ReviewExportLimitError extends Error {}

export interface ExportedReview {
  id: string;
  authorSubject: string;
  title: string;
  description: string;
  status: "validated" | "dismissed";
  createdAt: string;
  validatedBy: string | null;
  reviewedBy: string;
  reviewedAt: string;
  reviewNote: string;
  evidence: Evidence[];
}

export interface FinalizedReviewCollection {
  commission: { id: string; name: string; status: "active" | "closed" };
  records: ExportedReview[];
}

type ExportRow = Omit<ExportedReview, "evidence"> & {
  evidenceJson: string | null;
};

/**
 * A complete bounded collection, not a misleading snapshot of the 50 most recent
 * observations. The tenant guard is repeated inside the data query to close a
 * revocation race after the commission metadata lookup.
 */
export async function collectFinalizedReviews(
  db: D1Database, subject: string, commissionId: string,
  limit: number = MAX_FINALIZED_REVIEW_EXPORT
): Promise<FinalizedReviewCollection | null> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_FINALIZED_REVIEW_EXPORT) {
    throw new ReviewExportLimitError("Invalid export limit");
  }
  if (!subject || !commissionId) return null;
  const commission = await getCommissionSummary(db, subject, commissionId);
  if (!commission) return null;

  const result = await db.prepare(`
    WITH picked AS (
      SELECT id, reviewed_at
      FROM observations
      WHERE commission_id = ? AND status IN ('validated', 'dismissed')
      ORDER BY reviewed_at ASC, id ASC LIMIT ?
    )
    SELECT o.id, o.author_subject AS authorSubject, o.title, o.description,
      o.status, o.created_at AS createdAt, o.validated_by AS validatedBy,
      o.reviewed_by AS reviewedBy, o.reviewed_at AS reviewedAt,
      o.review_note AS reviewNote, e.reference_json AS evidenceJson
    FROM picked p
    JOIN observations o ON o.id = p.id AND o.commission_id = ?
    JOIN commission_members m ON m.commission_id = o.commission_id
      AND m.subject = ? AND m.active = 1
    LEFT JOIN observation_evidence e ON e.observation_id = o.id
    ORDER BY p.reviewed_at ASC, o.id ASC, e.created_at ASC, e.id ASC
  `).bind(commissionId, limit + 1, commissionId, subject).all<ExportRow>();

  // The member may be revoked while D1 fetches the export rows. Checking
  // membership inside that query alone is insufficient: an empty result
  // would still expose the commission metadata fetched above, and a
  // completed query could return sensitive rows after revocation.
  // Recheck before assembling the collection, with no further awaits here.
  // API callers must revalidate again after any asynchronous serialization
  // or hashing before returning a download.
  const currentCommission = await getCommissionSummary(db, subject, commissionId);
  if (!currentCommission) return null;

  const grouped = new Map<string, ExportedReview>();
  for (const row of result.results) {
    let record = grouped.get(row.id);
    if (!record) {
      if (grouped.size >= limit) {
        throw new ReviewExportLimitError("Report exceeds complete export limit");
      }
      record = {
        id: row.id, authorSubject: row.authorSubject,
        title: row.title, description: row.description, status: row.status,
        createdAt: row.createdAt, validatedBy: row.validatedBy,
        reviewedBy: row.reviewedBy, reviewedAt: row.reviewedAt,
        reviewNote: row.reviewNote, evidence: []
      };
      grouped.set(row.id, record);
    }
    if (row.evidenceJson !== null) {
      const evidence = JSON.parse(row.evidenceJson) as Evidence;
      if (evidence.commissionId !== commissionId) {
        throw new Error("Corrupted cross-commission evidence");
      }
      record.evidence.push(evidence);
    }
  }

  return {
    commission: { id: currentCommission.id, name: currentCommission.name, status: currentCommission.status },
    records: Array.from(grouped.values())
  };
}
