/**
 * Current authority for asynchronous operations is read from the durable,
 * append-only D1 denylist. Failure to read D1 is fatal (never assume active).
 * SQL transition guards independently close races against concurrent writes.
 */
export async function areOperatorSubjectsRevoked(
  db:D1Database,firstSubject:string,secondSubject=firstSubject
):Promise<boolean> {
  const result=await db.prepare(`
    SELECT 1 AS revoked FROM processing_redrive_revocations
    WHERE kind='operator' AND (target=? OR target=?)
    LIMIT 1
  `).bind(firstSubject,secondSubject).first<{revoked:number}>();
  return result!==null;
}
