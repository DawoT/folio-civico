/**
 * Count the complete eligible queue for a verified subject and commission.
 * This SQL query is scoped by ACTIVE membership and the commission state.
 * Callers must additionally distinguish a missing membership from a genuine
 * zero, and revalidate authorization after this await before publishing.
 */
export async function countReviewableObservations(
  db:D1Database,subject:string,commissionId:string
):Promise<number> {
  if (!subject?.trim() || !commissionId?.trim()) {
    throw new Error("Missing subject or commission");
  }
  const result=await db.prepare(`
    SELECT COUNT(*) AS count
    FROM observations o
    INNER JOIN commission_members m ON m.commission_id=o.commission_id
      AND m.subject=? AND m.active=1
    INNER JOIN commissions c ON c.id=o.commission_id
      AND c.status='active'
    WHERE o.commission_id=? AND o.status='in_review'
      AND o.author_subject<>?
      AND m.role IN ('president','member')
  `).bind(subject,commissionId,subject).first<{count:number}>();
  if(!result || !Number.isSafeInteger(result.count) || result.count<0) {
    throw new Error("Invalid review count");
  }
  return result.count;
}
