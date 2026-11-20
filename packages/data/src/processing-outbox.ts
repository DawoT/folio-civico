/** Durable outbox dispatch to Cloudflare Queues. The original PDF stays in private R2.
 * Ordinary messages carry only version ID and SHA-256. An isolated manual
 * redrive adds one opaque D1 reservation ID. Neither carries filenames,
 * object keys, JWTs, PDF bytes, reviewer identity or extracted text.
 */
export interface ProcessingQueueMessage {
  kind:"folio.process.pdf";
  versionId:string;
  sourceSha256:string;
  /** Only one-shot manual redrive messages carry this opaque D1 claim ID. */
  manualRedriveId?:string;
}
export interface OutboxDispatchSummary { selected:number; sent:number; failed:number }
interface OutboxRow {
  versionId:string;
  sourceSha256:string;
  state:"pending"|"sent";
  attempts:number;
  lastSentAt:string|null;
}
const MAX_BATCH=10;
const MAX_ATTEMPTS=10;
const REDELIVERY_MS=15*60*1000;

export async function dispatchProcessingOutbox(
  db:D1Database,queue:Pick<Queue<ProcessingQueueMessage>,"send">,
  now:Date=new Date()
):Promise<OutboxDispatchSummary>{
  if(!Number.isFinite(now.getTime()))throw new Error("Invalid dispatch clock");
  const expiredAt=new Date(now.getTime()-REDELIVERY_MS).toISOString();
  const rows=await db.prepare(`
    SELECT o.document_version_id AS versionId,v.sha256 AS sourceSha256,
      o.state,o.attempts,o.last_sent_at AS lastSentAt
    FROM document_processing_outbox o
    JOIN document_versions v ON v.id=o.document_version_id
    JOIN documents d ON d.id=v.document_id
    JOIN commissions c ON c.id=d.commission_id
    WHERE c.status='active' AND v.extraction_status='pending'
      AND o.attempts < ?
      AND ((o.state='pending' AND o.attempts=0 AND o.last_sent_at IS NULL)
        OR (o.state='sent' AND o.attempts>=1 AND o.last_sent_at <= ?))
    ORDER BY o.attempts ASC,o.created_at ASC,o.document_version_id ASC
    LIMIT ?
  `).bind(MAX_ATTEMPTS,expiredAt,MAX_BATCH).all<OutboxRow>();
  const sentAt=now.toISOString();
  let sent=0,failed=0;
  for(const item of rows.results){
    // Claim the row *before* sending: two scheduled Workers can select the
    // same pending item, but only one can win the conditional D1 UPDATE.
    // If this Worker crashes after the claim, the 15-minute lease expires
    // and the next dispatch re-sends safely with at-least-once semantics.
    const claimed=await db.prepare(`
      UPDATE document_processing_outbox
      SET state='sent',attempts=attempts+1,last_sent_at=?
      WHERE document_version_id=? AND state=? AND attempts=?
        AND last_sent_at IS ?
        AND attempts<? AND
          ((state='pending' AND attempts=0 AND last_sent_at IS NULL)
            OR (state='sent' AND attempts>=1 AND last_sent_at<=?))
        AND EXISTS (
          SELECT 1 FROM document_versions v
          JOIN documents d ON d.id=v.document_id
          JOIN commissions c ON c.id=d.commission_id
          WHERE v.id=document_processing_outbox.document_version_id
            AND v.extraction_status='pending' AND c.status='active'
        )
    `).bind(sentAt,item.versionId,item.state,item.attempts,
      item.lastSentAt,MAX_ATTEMPTS,expiredAt).run();
    if(!claimed.success || !Number.isSafeInteger(claimed.meta.changes)
      || claimed.meta.changes>1) {
      throw new Error("Outbox atomic claim failed");
    }
    if(claimed.meta.changes===0)continue;
    try{
      await queue.send({
        kind:"folio.process.pdf",versionId:item.versionId,
        sourceSha256:item.sourceSha256
      });
      sent++;
    }catch{
      failed++;
      // Definite send failure: restore eligibility without consuming an
      // attempt. CAS ensures this cannot reopen a completed or newer claim.
      // If D1 is unavailable, leave the lease in place for later redelivery.
      try{
        await db.prepare(`
          UPDATE document_processing_outbox
          SET state=?,attempts=?,last_sent_at=?
          WHERE document_version_id=? AND state='sent'
            AND attempts=? AND last_sent_at=?
            AND EXISTS (
              SELECT 1 FROM document_versions v
              WHERE v.id=document_processing_outbox.document_version_id
                AND v.extraction_status='pending'
            )
        `).bind(item.state,item.attempts,item.lastSentAt,
          item.versionId,item.attempts+1,sentAt).run();
      }catch{
        // Claim expires naturally; no document data enters logs or Queue.
      }
    }
  }
  return {selected:rows.results.length,sent,failed};
}
