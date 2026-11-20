import type {ProcessingQueueMessage} from "./processing-outbox";
import {isVerifiedRedriveAuthorization,type VerifiedRedriveAuthorization} from "@folio/auth";
import {isManualRedriveRevoked} from "./redrive-revocations";
import {isAsyncRedriveApproverRevoked} from "./async-redrive";
import {isInstitutionalApprovalInvalidated} from "./institutional-approval-journal";

/**
 * Internal, isolated operator operation only. This function is deliberately
 * NOT wired to API/MCP/cron/Queue consumers or live Wrangler bindings.
 *
 * The caller MUST supply an ephemeral proof from @folio/auth verifying
 * Access plus independent approval/MFA and inspector-release statements.
 * Signatures prove only what their trusted issuers attest: the issuer's
 * real MFA/CVE procedures still require an external audit. No remote host
 * or release authority is currently configured.
 */
export class ManualRedriveAccessError extends Error {}
export class ManualRedriveConflictError extends Error {}
export class ManualRedriveInputError extends Error {}

export interface ManualRedriveEnv {
  DB:D1Database;
  /** Narrow port allows a fake Queue, never a raw DLQ consumer. */
  QUEUE:{send(message:ProcessingQueueMessage):Promise<unknown>};
  /** Runtime-sealed proof, issued only after three signed authorities verify. */
  authorization?:VerifiedRedriveAuthorization;
  /** Trusted runtime digest of the actual inspector image, not user input. */
  requiredInspectorImageDigest?:string;
  /** R2.11: signed, independently approved D1 proposal; never client input. */
  asyncRequest?:{id:string;approvalDigest:string};
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
  asyncRequestId:string|null;
  asyncApprovalDigest:string|null;
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
  if(!isVerifiedRedriveAuthorization(env.authorization,{
    operatorSubject:input.operatorSubject,commissionId:input.commissionId,
    reviewId:input.reviewId,requestKey:input.requestKey,
    approvalRef:input.operatorApprovalRef,
    imageDigest:env.requiredInspectorImageDigest??""
  }) || !env.QUEUE || typeof env.QUEUE.send!=="function") {
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
      request_sha256 AS requestHash,state,
      async_request_id AS asyncRequestId,async_approval_sha256 AS asyncApprovalDigest
    FROM processing_manual_redrives
    WHERE operator_subject=? AND request_key=?
  `).bind(input.operatorSubject,input.requestKey).first<OldRequest>();
  if(!row)return null;
  if(row.requestHash!==hash || row.reviewId!==input.reviewId
    || row.commissionId!==input.commissionId
    || row.asyncRequestId!==(env.asyncRequest?.id??null)
    || row.asyncApprovalDigest!==(env.asyncRequest?.approvalDigest??null)) {
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
  // A previously verified signature can be revoked after issuance. Check
  // before ANY replay or mutation; D1 outages deny access, never bypass it.
  try{
    if(await isManualRedriveRevoked(env.DB,env.authorization!)
      || (env.asyncRequest && await isAsyncRedriveApproverRevoked(env.DB,env.asyncRequest.id))
      || (env.asyncRequest && await isInstitutionalApprovalInvalidated(
        env.DB,"redrive",env.asyncRequest.id
      ))){
      throw new Error("Revoked");
    }
  }catch{
    throw new ManualRedriveAccessError("Manual redrive authorization unavailable or revoked");
  }
  if(env.asyncRequest && (!/^[0-9a-f-]{36}$/.test(env.asyncRequest.id)
    || !/^[a-f0-9]{64}$/.test(env.asyncRequest.approvalDigest))){
    throw new ManualRedriveAccessError("Independent redrive approval missing");
  }
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
          operator_subject,request_key,operator_approval_ref,request_sha256,
          authorization_sha256,image_digest,
          approval_key_thumbprint,release_key_thumbprint,
          async_request_id,async_approval_sha256
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      `).bind(id,input.commissionId,input.reviewId,row.versionId,row.sourceSha256,
        input.operatorSubject,input.requestKey,input.operatorApprovalRef,hash,
        env.authorization!.attestationDigest,
        env.authorization!.imageDigest,env.authorization!.approvalKeyThumbprint,
        env.authorization!.releaseKeyThumbprint,
        env.asyncRequest?.id??null,env.asyncRequest?.approvalDigest??null),
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
  // If the revocation lookup fails here, leave the durable reservation in
  // place without Queue.send; a subsequent replay cannot resend it.
  const revoked=await isManualRedriveRevoked(env.DB,env.authorization!)
    || (env.asyncRequest && await isAsyncRedriveApproverRevoked(env.DB,env.asyncRequest.id))
    || (env.asyncRequest && await isInstitutionalApprovalInvalidated(
      env.DB,"redrive",env.asyncRequest.id
    ));
  if(revoked || !verified || verified.versionId!==row.versionId
    || verified.sourceSha256!==row.sourceSha256
    || !isVerifiedRedriveAuthorization(env.authorization,{
      operatorSubject:input.operatorSubject,commissionId:input.commissionId,
      reviewId:input.reviewId,requestKey:input.requestKey,
      approvalRef:input.operatorApprovalRef,
      imageDigest:env.requiredInspectorImageDigest??""
    })) {
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
