/**
 * Internal, read-only reconciliation of institutionally invalidated redrives.
 * NOT a public endpoint, case authority, Queue consumer, or permission grant.
 * Returned states describe only the local one-shot ledger, never delivery
 * confirmation or downstream processing of a potentially sent message.
 */
export type InstitutionalRedriveLedgerState =
  "not_reserved"|"reserved"|"halted"|"sent"|"uncertain";

export type InstitutionalInvalidationReason =
  "case_closed"|"case_superseded"|"reviewer_withdrawn"|"authority_withdrawn";

export interface InvalidatedRedriveRecord {
  readonly requestId:string;
  readonly redriveId:string|null;
  readonly state:InstitutionalRedriveLedgerState;
  readonly reason:InstitutionalInvalidationReason;
  readonly invalidationRevision:number;
  readonly invalidatedAt:number;
}

export interface InstitutionalRedriveReconciliationPage {
  readonly items:ReadonlyArray<InvalidatedRedriveRecord>;
  readonly nextCursor:string|null;
}

export interface InstitutionalRedriveReconciliationFilter {
  readonly afterRequestId?:string;
  readonly limit?:number;
}
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

type Row=Omit<InvalidatedRedriveRecord,"state"> & {
  state:Exclude<InstitutionalRedriveLedgerState,"not_reserved">|null
};

/**
 * Bounded keyset scan, with an opaque request ID cursor and no human subjects,
 * source hashes, tokens, or case contents. A D1 outage fails the entire read.
 * Only a trusted operator service may call this directly in a future design.
 */
export async function listInstitutionalRedriveReconciliation(
  db:D1Database,
  filter:InstitutionalRedriveReconciliationFilter={}
):Promise<InstitutionalRedriveReconciliationPage>{
  const limit=filter.limit??50;
  if(!Number.isSafeInteger(limit) || limit<1 || limit>100
    || (filter.afterRequestId!==undefined && !UUID.test(filter.afterRequestId))){
    throw new RangeError("Invalid institutional reconciliation page");
  }
  const result=await db.prepare(`
    SELECT i.request_id AS requestId,
      i.case_revision AS invalidationRevision,
      i.reason AS reason,i.invalidated_at AS invalidatedAt,
      m.id AS redriveId,m.state AS state
    FROM processing_institutional_approval_invalidations i
    LEFT JOIN processing_manual_redrives m ON m.async_request_id=i.request_id
    WHERE i.purpose='redrive' AND i.request_id>?
    ORDER BY i.request_id ASC LIMIT ?
  `).bind(filter.afterRequestId??"",limit+1).all<Row>();
  if(!result.success)throw new Error("Institutional reconciliation D1 read failed");
  const hasNext=result.results.length>limit;
  const items=result.results.slice(0,limit).map(row=>Object.freeze({
    ...row,state:row.state??"not_reserved"
  }));
  return Object.freeze({
    items:Object.freeze(items),
    nextCursor:hasNext ? items[items.length-1]!.requestId : null
  });
}
