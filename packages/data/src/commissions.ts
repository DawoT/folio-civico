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
