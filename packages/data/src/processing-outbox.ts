/** Durable outbox dispatch to Cloudflare Queues. The original PDF stays in private R2.
 * Queue messages carry only version ID and expected SHA-256; never filenames,
 * object keys, PDF bytes, reviewer identity or extracted text.
 */
export interface ProcessingQueueMessage {
  kind:"folio.process.pdf";
  versionId:string;
  sourceSha256:string;
}
export interface OutboxDispatchSummary { selected:number; sent:number; failed:number }
interface OutboxRow { versionId:string; sourceSha256:string }
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
    SELECT o.document_version_id AS versionId,v.sha256 AS sourceSha256
    FROM document_processing_outbox o
    JOIN document_versions v ON v.id=o.document_version_id
    JOIN documents d ON d.id=v.document_id
    JOIN commissions c ON c.id=d.commission_id
    WHERE c.status='active' AND v.extraction_status='pending'
      AND o.attempts < ?
      AND (o.state='pending' OR (o.state='sent' AND o.last_sent_at <= ?))
    ORDER BY o.attempts ASC,o.created_at ASC,o.document_version_id ASC
    LIMIT ?
  `).bind(MAX_ATTEMPTS,expiredAt,MAX_BATCH).all<OutboxRow>();
  let sent=0,failed=0;
  for(const item of rows.results){
    try{
      await queue.send({
        kind:"folio.process.pdf",versionId:item.versionId,
        sourceSha256:item.sourceSha256
      });
      // At-least-once: a crash between send and this UPDATE can redeliver.
      // The queue consumer and signed document admission are idempotent.
      await db.prepare(`
        UPDATE document_processing_outbox
        SET state='sent',attempts=attempts+1,last_sent_at=?
        WHERE document_version_id=? AND state IN ('pending','sent') AND attempts<?
      `).bind(now.toISOString(),item.versionId,MAX_ATTEMPTS).run();
      sent++;
    }catch{
      // Do not log the document ID or its hash. The durable row remains
      // pending or sent for later retries, subject to operator limits.
      failed++;
    }
  }
  return {selected:rows.results.length,sent,failed};
}
