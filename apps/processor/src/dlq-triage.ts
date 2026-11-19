import {parseProcessingMessage} from "./consumer";

/**
 * Read-only DLQ triage. A result is not authorization to redrive or delete.
 * The caller must be an isolated, approved operator: this function is not
 * reachable through the public Worker, the MCP server or an active Queue.
 */
export type DLQDisposition =
  | "invalid_message"
  | "not_found"
  | "source_mismatch"
  | "missing_outbox"
  | "inconsistent"
  | "paused"
  | "rejected"
  | "completed"
  | "automatic_retry_pending"
  | "manual_review_exhausted";

export interface DeadLetterTriageReport {
  scanned:number;
  counts:Record<DLQDisposition,number>;
  /** Positional classifications only. Never expose IDs or document metadata. */
  items:Array<{position:number;disposition:DLQDisposition}>;
  requiresOperatorAttention:boolean;
}

interface TriageRow {
  sourceSha256:string;
  versionStatus:string;
  commissionStatus:string;
  outboxState:string|null;
  attempts:number|null;
  lastSentAt:string|null;
  hasReport:number;
}

const MAX_MESSAGES=50;

/**
 * Classify a bounded, operator-supplied snapshot of DLQ payloads by looking
 * up current D1 state. Makes no R2/Queue calls, writes, acknowledgements or
 * replay decisions. A state can change immediately after this snapshot.
 */
export async function triageDeadLetterMessages(
  db:D1Database,
  messages:readonly unknown[],
  now:Date=new Date()
):Promise<DeadLetterTriageReport> {
  if(!Number.isFinite(now.getTime()))throw new Error("Invalid DLQ triage clock");
  if(!Array.isArray(messages)||messages.length<1||messages.length>MAX_MESSAGES) {
    throw new Error("DLQ triage requires 1-50 messages");
  }
  const counts:Record<DLQDisposition,number>={
    invalid_message:0,not_found:0,source_mismatch:0,missing_outbox:0,
    inconsistent:0,paused:0,rejected:0,completed:0,
    automatic_retry_pending:0,manual_review_exhausted:0
  };
  const items:DeadLetterTriageReport["items"]=[];
  for(let position=0;position<messages.length;position++) {
    const message=parseProcessingMessage(messages[position]);
    let disposition:DLQDisposition;
    if(!message) {
      disposition="invalid_message";
    } else {
      const row=await db.prepare(`
        SELECT v.sha256 AS sourceSha256,v.extraction_status AS versionStatus,
          c.status AS commissionStatus,o.state AS outboxState,
          o.attempts,o.last_sent_at AS lastSentAt,
          CASE WHEN r.document_version_id IS NULL THEN 0 ELSE 1 END AS hasReport
        FROM document_versions v
        JOIN documents d ON d.id=v.document_id
        JOIN commissions c ON c.id=d.commission_id
        LEFT JOIN document_processing_outbox o ON o.document_version_id=v.id
        LEFT JOIN document_processing_reports r ON r.document_version_id=v.id
        WHERE v.id=?
      `).bind(message.versionId).first<TriageRow>();
      if(!row) disposition="not_found";
      else if(row.sourceSha256!==message.sourceSha256) disposition="source_mismatch";
      else if(row.commissionStatus!=="active") disposition="paused";
      else if(row.versionStatus==="needs_review"||row.versionStatus==="failed") {
        disposition="rejected";
      } else if(row.versionStatus==="ready") {
        disposition=row.outboxState==="completed" && row.hasReport===1
          ?"completed":"inconsistent";
      } else if(row.versionStatus!=="pending") {
        disposition="inconsistent";
      } else if(row.outboxState===null) {
        disposition="missing_outbox";
      } else if(row.hasReport!==0) {
        disposition="inconsistent";
      } else if(row.outboxState==="pending" && row.attempts===0
        && row.lastSentAt===null) {
        disposition="automatic_retry_pending";
      } else if(row.outboxState==="sent"
        && Number.isSafeInteger(row.attempts) && row.attempts!==null
        && row.attempts>=1 && row.attempts<=10
        && typeof row.lastSentAt==="string"
        && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(row.lastSentAt)
        && Number.isFinite(Date.parse(row.lastSentAt))
        && new Date(Date.parse(row.lastSentAt)).toISOString()===row.lastSentAt
        && Date.parse(row.lastSentAt)<=now.getTime()+60_000) {
        disposition=row.attempts===10?"manual_review_exhausted":"automatic_retry_pending";
      } else {
        disposition="inconsistent";
      }
    }
    items.push({position,disposition});
    counts[disposition]++;
  }
  return {
    scanned:items.length,counts,items,
    requiresOperatorAttention:items.some(({disposition})=>
      disposition!=="automatic_retry_pending" && disposition!=="completed")
  };
}
