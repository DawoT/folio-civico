import type { MemberRole } from "@folio/domain";

export interface CommissionSummary {
  id: string;
  name: string;
  status: "active" | "closed";
  role: MemberRole;
}

export async function getCommissionSummary(
  db: D1Database,
  subject: string,
  commissionId: string
): Promise<CommissionSummary | null> {
  if (!subject?.trim() || !commissionId?.trim()) {
    throw new Error("Subject and commission are required");
  }

  // Binding both IDs prevents enumeration and cross-commission reads.
  return db.prepare(`
    SELECT c.id, c.name, c.status, m.role
    FROM commissions c
    INNER JOIN commission_members m ON m.commission_id = c.id
    WHERE c.id = ? AND m.subject = ? AND m.active = 1
    LIMIT 1
  `).bind(commissionId, subject).first<CommissionSummary>();
}


export interface CommissionBatch {
  id: string;
  label: string;
}

/** Never enumerate commissions from request parameters: derive the list from verified subject. */
export async function listAccessibleCommissions(db: D1Database, subject: string): Promise<CommissionSummary[]> {
  if (!subject?.trim()) throw new Error("Missing verified subject");
  const rows = await db.prepare(`
    SELECT c.id, c.name, c.status, m.role
    FROM commissions c
    INNER JOIN commission_members m ON m.commission_id = c.id
    WHERE m.subject = ? AND m.active = 1
    ORDER BY CASE c.status WHEN 'active' THEN 0 ELSE 1 END, c.name, c.id
    LIMIT 50
  `).bind(subject).all<CommissionSummary>();
  return rows.results;
}

export async function listCommissionBatches(
  db: D1Database, subject: string, commissionId: string
): Promise<CommissionBatch[]> {
  if (!subject?.trim() || !commissionId?.trim()) throw new Error("Missing verified subject or commission");
  const rows = await db.prepare(`
    SELECT b.id, b.label
    FROM document_batches b
    INNER JOIN commission_members m ON m.commission_id = b.commission_id
    WHERE b.commission_id = ? AND m.subject = ? AND m.active = 1
    ORDER BY b.created_at DESC, b.id DESC
    LIMIT 100
  `).bind(commissionId, subject).all<CommissionBatch>();
  return rows.results;
}
