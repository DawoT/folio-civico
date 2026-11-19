import type {ProcessingQueueMessage} from "./processing-outbox";
import {validAccessSubject} from "./membership";

/**
 * Internal, isolated operator operation only. This function is deliberately
 * NOT wired to API/MCP/cron/Queue consumers or live Wrangler bindings.
 *
 * The caller MUST supply independently verified Access identity and a
 * separately approved inspector release gate. Checking these configured
 * values is NOT equivalent to verifying Access/MFA, security CVEs, or a
 * human operator's approval ticket. No remote integration exists.
 */
export class ManualRedriveAccessError extends Error {}
export class ManualRedriveConflictError extends Error {}
export class ManualRedriveInputError extends Error {}

export interface ManualRedriveEnv {
  DB:D1Database;
  /** Narrow port allows a fake Queue, never a raw DLQ consumer. */
  QUEUE:{send(message:ProcessingQueueMessage):Promise<unknown>};
  /** Configured outside any request; absent in current runtime. */
  configuredOperatorSubject?:string;
  /** Externally authorized release switch; absent/false by default. */
  inspectorReleaseApproved?:boolean;
}
export interface OneShotRedriveInput {
  commissionId:string;
  reviewId:string;
  /** Verified by an upstream Access integration, not user-submitted. */
  operatorSubject:string;
  requestKey:string;
  /** Separate operator incident approval; reference only, not proof. */
  operatorApprovalRef:string;
}
export interface ManualRedriveResult {
  id:string;
  state:"reserved"|"sent"|"uncertain"|"halted";
  replayed:boolean;
}
interface OldRequest {
  id:string;
  commissionId:string;
  reviewId:string;
  requestHash:string;
  state:ManualRedriveResult["state"];
}
interface ReviewRow {
  versionId:string;
  sourceSha256:string;
}
const ID=/^[A-Za-z0-9_-]{1,64}$/;
const KEY=/^[A-Za-z0-9_-]{8,96}$/;
const APPROVAL=/^OPR_[A-Za-z0-9_-]{8,60}$/;

async function digest(parts:string[]):Promise<string> {
  const bytes=new TextEncoder().encode(JSON.stringify(parts));
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))]
    .map(x=>x.toString(16).padStart(2,"0")).join("");
}
function requireAuthorization(env:ManualRedriveEnv,input:OneShotRedriveInput):void {
  if(!validAccessSubject(input.operatorSubject)
    || !validAccessSubject(env.configuredOperatorSubject)
    || input.operatorSubject!==env.configuredOperatorSubject
    || env.inspectorReleaseApproved!==true
    || !env.QUEUE || typeof env.QUEUE.send!=="function") {
    throw new ManualRedriveAccessError("Explicit independent operator release is required");
  }
}
function requireInput(input:OneShotRedriveInput):void {
  if(!ID.test(input.commissionId)||!ID.test(input.reviewId)
    || !KEY.test(input.requestKey)||!APPROVAL.test(input.operatorApprovalRef)) {
    throw new ManualRedriveInputError("Invalid case, idempotency key or operator approval");
  }
}
async function previous(env:ManualRedriveEnv,input:OneShotRedriveInput,hash:string)
:Promise<ManualRedriveResult|null>{
  const row=await env.DB.prepare(`
    SELECT id,commission_id AS commissionId,recovery_review_id AS reviewId,
      request_sha256 AS requestHash,state
    FROM processing_manual_redrives
    WHERE operator_subject=? AND request_key=?
  `).bind(input.operatorSubject,input.requestKey).first<OldRequest>();
  if(!row)return null;
  if(row.requestHash!==hash || row.reviewId!==input.reviewId
    || row.commissionId!==input.commissionId) {
    throw new ManualRedriveConflictError("Idempotency key belongs to another operation");
  }
  return {id:row.id,state:row.state,replayed:true};
}

async function stillEligible(
  db:D1Database,reviewId:string,commissionId:string,operator:string
):Promise<ReviewRow|null> {
  return db.prepare(`
    SELECT v.id AS versionId,v.sha256 AS sourceSha256
    FROM processing_recovery_reviews r
    JOIN commissions c ON c.id=r.commission_id
    JOIN document_versions v ON v.id=r.document_version_id
    JOIN documents d ON d.id=v.document_id
    JOIN document_processing_outbox o ON o.document_version_id=v.id
    JOIN commission_members sponsor ON sponsor.commission_id=c.id
    JOIN commission_members reviewer ON reviewer.commission_id=c.id
    WHERE r.id=? AND r.commission_id=? AND d.commission_id=r.commission_id
      AND r.status='endorsed_for_operator_review' AND c.status='active'
      AND v.extraction_status='pending' AND v.sha256=r.source_sha256
      AND o.state='sent' AND o.attempts=10 AND o.last_sent_at IS NOT NULL
      AND sponsor.subject=r.requested_by AND sponsor.active=1 AND sponsor.role='president'
      AND reviewer.subject=r.reviewed_by AND reviewer.active=1
      AND reviewer.role IN ('president','member')
      AND r.reviewed_by<>r.requested_by AND r.requested_by<>?
      AND r.reviewed_by<>?
      AND NOT EXISTS(
        SELECT 1 FROM commission_members m
        WHERE m.commission_id=c.id AND m.subject=?
      )
      AND NOT EXISTS(
        SELECT 1 FROM document_processing_reports report
        WHERE report.document_version_id=v.id
      )
  `).bind(reviewId,commissionId,operator,operator,operator).first<ReviewRow>();
}

async function finalize(
  env:ManualRedriveEnv,id:string,commissionId:string,operator:string,
  state:"sent"|"uncertain"|"halted"
):Promise<void>{
  try{
    const result=await env.DB.batch([
      env.DB.prepare(`
        UPDATE processing_manual_redrives
        SET state=?,outcome_at=?
        WHERE id=? AND commission_id=? AND operator_subject=? AND state='reserved'
      `).bind(state,new Date().toISOString(),id,commissionId,operator),
      env.DB.prepare(`
        INSERT INTO audit_events(
          id,commission_id,actor_subject,action,resource_type,resource_id,metadata_json
        ) SELECT ?,?,?,'processing.manual_redrive_outcome','manual_redrive',?,
          json_object('state',?) WHERE changes()=1
      `).bind(crypto.randomUUID(),commissionId,operator,id,state)
    ]);
    if(result.length!==2 || result.some(x=>!x.success||x.meta.changes!==1)) {
      throw new Error("Incomplete manual redrive finalization");
    }
  }catch{
    // The D1 reservation remains durable. Never enqueue again when the
    // final D1 write fails, regardless of Queue's ambiguous outcome.
    throw new ManualRedriveConflictError("Manual redrive outcome requires reconciliation");
  }
}

export async function executeOneShotManualRedrive(
  env:ManualRedriveEnv,input:OneShotRedriveInput
):Promise<ManualRedriveResult> {
  // Access identity, configured operator and inspector release are provided
  // by a FUTURE trusted host. No public caller can currently reach this.
  requireAuthorization(env,input);
  requireInput(input);
  const hash=await digest([
    input.commissionId,input.reviewId,input.operatorSubject,
    input.operatorApprovalRef
  ]);
  const prior=await previous(env,input,hash);
  if(prior)return prior;
  const row=await stillEligible(
    env.DB,input.reviewId,input.commissionId,input.operatorSubject
  );
  if(!row)throw new ManualRedriveConflictError("Review stale or not eligible");

  const id=crypto.randomUUID();
  try{
    const results=await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO processing_manual_redrives(
          id,commission_id,recovery_review_id,document_version_id,source_sha256,
          operator_subject,request_key,operator_approval_ref,request_sha256
        ) VALUES(?,?,?,?,?,?,?,?,?)
      `).bind(id,input.commissionId,input.reviewId,row.versionId,row.sourceSha256,
        input.operatorSubject,input.requestKey,input.operatorApprovalRef,hash),
      env.DB.prepare(`
        INSERT INTO audit_events(
          id,commission_id,actor_subject,action,resource_type,resource_id,metadata_json
        ) SELECT ?,?,?,'processing.manual_redrive_reserved','manual_redrive',?,
          json_object('state','reserved') WHERE changes()=1
      `).bind(crypto.randomUUID(),input.commissionId,input.operatorSubject,id)
    ]);
    if(results.length!==2 || results.some(x=>!x.success||x.meta.changes!==1)){
      throw new Error("Incomplete manual redrive claim");
    }
  }catch{
    const concurrent=await previous(env,input,hash);
    if(concurrent)return concurrent;
    throw new ManualRedriveConflictError("Manual redrive was already reserved or became stale");
  }

  // A state may have changed since the CAS reservation. This second check
  // narrows the authorization window; it cannot be atomic with Queue.send.
  const verified=await stillEligible(
    env.DB,input.reviewId,input.commissionId,input.operatorSubject
  );
  if(!verified || verified.versionId!==row.versionId
    || verified.sourceSha256!==row.sourceSha256) {
    await finalize(env,id,input.commissionId,input.operatorSubject,"halted");
    return {id,state:"halted",replayed:false};
  }

  let outcome:"sent"|"uncertain"="sent";
  try {
    await env.QUEUE.send({
      kind:"folio.process.pdf",versionId:row.versionId,
      sourceSha256:row.sourceSha256
    });
  } catch {
    // A network rejection might mean "accepted, reply lost". Retrying
    // automatically here would violate the one-shot operational limit.
    outcome="uncertain";
  }
  await finalize(env,id,input.commissionId,input.operatorSubject,outcome);
  return {id,state:outcome,replayed:false};
}
