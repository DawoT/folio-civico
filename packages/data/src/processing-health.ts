/**
 * Bounded, read-only operational diagnostics for the PDF processing outbox.
 * This is intentionally NOT a recovery or redrive API. No document identifiers,
 * R2 object keys, hashes, subjects, filenames or page text are returned.
 */
export interface ProcessingBacklogOptions {
  now?:Date;
  maxRows?:number;
}
export interface ProcessingBacklogReport {
  complete:boolean;
  scanned:number;
  untrackedPending:number;
  pendingFresh:number;
  pendingOverdue:number;
  inFlight:number;
  retryDue:number;
  exhausted:number;
  rejected:number;
  paused:number;
  completed:number;
  inconsistent:number;
  needsAttention:boolean;
}
interface BacklogRow {
  state:string;
  attempts:number;
  lastSentAt:string|null;
  createdAt:string;
  versionStatus:string;
  commissionStatus:string;
  hasReport:number;
}
const MAX_ROWS=2000;
const DEFAULT_ROWS=1000;
const SEND_LEASE_MS=15*60*1000;
const PENDING_ALERT_MS=30*60*1000;
const CLOCK_SKEW_MS=60*1000;

/** D1 uses SQLite timestamps in UTC; ISO-8601 timestamps also supported. */
function timestamp(value:string|null):number|null {
  if(typeof value!=="string")return null;
  const normalized=/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)
    ? value.replace(" ","T")+"Z"
    : value;
  if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(normalized))return null;
  const result=Date.parse(normalized);
  if(!Number.isFinite(result))return null;
  // Date.parse normalizes impossible calendar dates (e.g. February 30).
  // Never classify such corrupted timestamps as a healthy queue lease.
  return new Date(result).toISOString().slice(0,19)===normalized.slice(0,19)
    ? result : null;
}

export async function auditProcessingBacklog(
  db:D1Database,options:ProcessingBacklogOptions={}
):Promise<ProcessingBacklogReport> {
  const now=options.now??new Date();
  const maxRows=options.maxRows??DEFAULT_ROWS;
  if(!Number.isFinite(now.getTime())
    || !Number.isSafeInteger(maxRows) || maxRows<1 || maxRows>MAX_ROWS) {
    throw new Error("Invalid processing audit bounds or clock");
  }
  // A strict page cap prevents an accidentally massive operator scan.
  const rows=await db.prepare(`
    SELECT o.state AS state,o.attempts AS attempts,
      o.last_sent_at AS lastSentAt,o.created_at AS createdAt,
      v.extraction_status AS versionStatus,c.status AS commissionStatus,
      CASE WHEN r.document_version_id IS NULL THEN 0 ELSE 1 END AS hasReport
    FROM document_processing_outbox o
    JOIN document_versions v ON v.id=o.document_version_id
    JOIN documents d ON d.id=v.document_id
    JOIN commissions c ON c.id=d.commission_id
    LEFT JOIN document_processing_reports r ON r.document_version_id=v.id
    ORDER BY o.created_at ASC,o.document_version_id ASC
    LIMIT ?
  `).bind(maxRows+1).all<BacklogRow>();

  // Count active pending versions that bypassed the guaranteed outbox trigger
  // due to legacy/manual corruption. Only an aggregate is ever selected.
  const missing=await db.prepare(`
    SELECT COUNT(*) AS count FROM document_versions v
    JOIN documents d ON d.id=v.document_id
    JOIN commissions c ON c.id=d.commission_id
    LEFT JOIN document_processing_outbox o ON o.document_version_id=v.id
    WHERE v.extraction_status='pending' AND c.status='active'
      AND o.document_version_id IS NULL
  `).first<{count:number}>();

  const report:ProcessingBacklogReport={
    complete:rows.results.length<=maxRows,
    scanned:0,untrackedPending:Number(missing?.count??0),
    pendingFresh:0,pendingOverdue:0,inFlight:0,retryDue:0,exhausted:0,
    rejected:0,paused:0,completed:0,inconsistent:0,needsAttention:false
  };
  const clock=now.getTime();
  for(const row of rows.results.slice(0,maxRows)) {
    report.scanned++;
    if(row.versionStatus==="ready" && row.state==="completed" && row.hasReport===1) {
      report.completed++;
      continue;
    }
    if(row.versionStatus==="needs_review" || row.versionStatus==="failed") {
      report.rejected++;
      continue;
    }
    if(row.commissionStatus==="closed" && row.versionStatus==="pending") {
      report.paused++;
      continue;
    }
    if(row.commissionStatus!=="active" || row.versionStatus!=="pending"
      || !Number.isSafeInteger(row.attempts) || row.attempts<0 || row.attempts>10
      || row.hasReport!==0
      || !["pending","sent"].includes(row.state)) {
      report.inconsistent++;
      continue;
    }
    const created=timestamp(row.createdAt);
    const sent=timestamp(row.lastSentAt);
    if(created===null || created>clock+CLOCK_SKEW_MS
      || (row.state==="pending" && (row.attempts!==0 || row.lastSentAt!==null))
      || (row.state==="sent" && (row.attempts<1 || sent===null || sent>clock+CLOCK_SKEW_MS))) {
      report.inconsistent++;
      continue;
    }
    if(row.attempts>=10) {
      report.exhausted++;
      continue;
    }
    if(row.state==="pending") {
      if(clock-created>=PENDING_ALERT_MS)report.pendingOverdue++;
      else report.pendingFresh++;
      continue;
    }
    if(sent===null) {
      report.inconsistent++;
      continue;
    }
    if(clock-sent>=SEND_LEASE_MS)report.retryDue++;
    else report.inFlight++;
  }
  report.needsAttention=!report.complete || report.untrackedPending>0
    || report.pendingOverdue>0 || report.retryDue>0 || report.exhausted>0
    || report.rejected>0 || report.inconsistent>0;
  return report;
}
