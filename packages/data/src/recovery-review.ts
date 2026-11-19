import {validAccessSubject} from "./membership";

/**
 * R2.4 is an INTERNAL, operator-mediated human review journal; never call this
 * with unverified subject strings from a browser or enqueue from its result.
 * Endorsement is not an inspection verdict and does not permit any redrive.
 */
export class RecoveryReviewAccessError extends Error {}
export class RecoveryReviewConflictError extends Error {}
export class RecoveryReviewInputError extends Error {}

export type RecoveryReviewStatus="in_review"|"endorsed_for_operator_review"|"dismissed";
export interface RecoveryReviewResult {
  id:string;
  status:RecoveryReviewStatus;
  replayed:boolean;
}
export interface OpenRecoveryReviewInput {
  commissionId:string;
  versionId:string;
  sourceSha256:string;
  actorSubject:string;
  incidentRef:string;
  requestKey:string;
}
export interface DecideRecoveryReviewInput {
  commissionId:string;
  reviewId:string;
  actorSubject:string;
  requestKey:string;
  decision:"endorse"|"dismiss";
  rationale:string;
}

interface ActiveRole {role:string;active:number;status:string}
interface ReviewState {
  id:string;status:RecoveryReviewStatus;requestedBy:string;
}
interface ActionRecord {
  reviewId:string;action:string;payloadSha256:string;
  resultStatus:RecoveryReviewStatus;
}

const ID=/^[A-Za-z0-9_-]{1,64}$/;
const REQUEST_KEY=/^[A-Za-z0-9_-]{8,96}$/;
const INCIDENT=/^[A-Za-z0-9_-]{8,64}$/;
const SHA=/^[a-f0-9]{64}$/;

async function digest(value:unknown):Promise<string>{
  const bytes=new TextEncoder().encode(JSON.stringify(value));
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))]
    .map(n=>n.toString(16).padStart(2,"0")).join("");
}
async function scope(db:D1Database,commissionId:string,actorSubject:string,
  roles:readonly string[]):Promise<void> {
  const row=await db.prepare(`
    SELECT m.role,m.active,c.status
    FROM commission_members m JOIN commissions c ON c.id=m.commission_id
    WHERE m.commission_id=? AND m.subject=?
  `).bind(commissionId,actorSubject).first<ActiveRole>();
  if(!row || row.active!==1 || !roles.includes(row.role)) {
    throw new RecoveryReviewAccessError("Active authorized commission membership required");
  }
  if(row.status!=="active") {
    throw new RecoveryReviewConflictError("Commission no longer active");
  }
}

async function prior(db:D1Database,commissionId:string,actorSubject:string,
  requestKey:string):Promise<ActionRecord|null> {
  return db.prepare(`
    SELECT review_id AS reviewId,action,payload_sha256 AS payloadSha256,
      result_status AS resultStatus
    FROM processing_recovery_actions
    WHERE commission_id=? AND actor_subject=? AND request_key=?
  `).bind(commissionId,actorSubject,requestKey).first<ActionRecord>();
}
function replay(old:ActionRecord|null,action:string,hash:string):RecoveryReviewResult|null {
  if(!old)return null;
  if(old.action!==action || old.payloadSha256!==hash){
    throw new RecoveryReviewConflictError("Idempotency key already used");
  }
  return {id:old.reviewId,status:old.resultStatus,replayed:true};
}
function validatedIdentity(input:{
  commissionId:string;actorSubject:string;requestKey:string
}):void {
  if(!ID.test(input.commissionId) || !validAccessSubject(input.actorSubject)
    || !REQUEST_KEY.test(input.requestKey)) {
    throw new RecoveryReviewInputError("Invalid actor, scope or request key");
  }
}
function requireBatchSuccess(results:D1Result<unknown>[]):void {
  if(results.length!==3 || results.some(result=>!result.success
    || result.meta.changes!==1)) {
    throw new RecoveryReviewConflictError("Recovery review changed concurrently");
  }
}

export async function openRecoveryReview(
  db:D1Database,input:OpenRecoveryReviewInput
):Promise<RecoveryReviewResult>{
  validatedIdentity(input);
  if(!ID.test(input.versionId) || !SHA.test(input.sourceSha256)
    || !INCIDENT.test(input.incidentRef)) {
    throw new RecoveryReviewInputError("Invalid version, source fingerprint or incident reference");
  }
  await scope(db,input.commissionId,input.actorSubject,["president"]);
  const hash=await digest(["open",input.versionId,input.sourceSha256,input.incidentRef]);
  const previous=replay(
    await prior(db,input.commissionId,input.actorSubject,input.requestKey),"open",hash
  );
  if(previous)return previous;
  const reviewId=crypto.randomUUID();
  try{
    const results=await db.batch([
      db.prepare(`
        INSERT INTO processing_recovery_reviews(
          id,commission_id,document_version_id,source_sha256,incident_ref,requested_by
        ) SELECT ?,?,?,?,?,?
        WHERE EXISTS (
          SELECT 1 FROM document_versions v
          JOIN documents d ON d.id=v.document_id
          JOIN commissions c ON c.id=d.commission_id
          JOIN commission_members m ON m.commission_id=c.id
          JOIN document_processing_outbox o ON o.document_version_id=v.id
          WHERE v.id=? AND d.commission_id=? AND v.sha256=?
            AND v.extraction_status='pending' AND c.status='active'
            AND m.subject=? AND m.active=1 AND m.role='president'
            AND o.state='sent' AND o.attempts=10 AND o.last_sent_at IS NOT NULL
            AND NOT EXISTS(
              SELECT 1 FROM document_processing_reports r
              WHERE r.document_version_id=v.id
            )
        )
      `).bind(reviewId,input.commissionId,input.versionId,input.sourceSha256,
        input.incidentRef,input.actorSubject,
        input.versionId,input.commissionId,input.sourceSha256,input.actorSubject),
      db.prepare(`
        INSERT INTO processing_recovery_actions(
          commission_id,actor_subject,request_key,review_id,action,payload_sha256,result_status
        ) SELECT ?,?,?,?,'open',?,'in_review' WHERE changes()=1
      `).bind(input.commissionId,input.actorSubject,input.requestKey,reviewId,hash),
      db.prepare(`
        INSERT INTO audit_events(
          id,commission_id,actor_subject,action,resource_type,resource_id,metadata_json
        ) SELECT ?,?,?,'processing.recovery_review_opened','recovery_review',?,
          json_object('status','in_review') WHERE changes()=1
      `).bind(crypto.randomUUID(),input.commissionId,input.actorSubject,reviewId)
    ]);
    requireBatchSuccess(results);
  }catch{
    const concurrent=replay(
      await prior(db,input.commissionId,input.actorSubject,input.requestKey),"open",hash
    );
    if(concurrent)return concurrent;
    throw new RecoveryReviewConflictError("Recovery review not eligible or already exists");
  }
  return {id:reviewId,status:"in_review",replayed:false};
}

export async function decideRecoveryReview(
  db:D1Database,input:DecideRecoveryReviewInput
):Promise<RecoveryReviewResult>{
  validatedIdentity(input);
  if(!ID.test(input.reviewId) || !["endorse","dismiss"].includes(input.decision)
    || typeof input.rationale!=="string"
    || input.rationale.trim().length<24 || input.rationale.trim().length>600
    || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(input.rationale)){
    throw new RecoveryReviewInputError("Invalid case, decision or rationale");
  }
  await scope(db,input.commissionId,input.actorSubject,["president","member"]);
  const caseRow=await db.prepare(`
    SELECT id,status,requested_by AS requestedBy FROM processing_recovery_reviews
    WHERE id=? AND commission_id=?
  `).bind(input.reviewId,input.commissionId).first<ReviewState>();
  if(!caseRow || caseRow.requestedBy===input.actorSubject){
    throw new RecoveryReviewAccessError("Review not found or segregation required");
  }
  const reasonDigest=await digest(input.rationale.trim());
  const hash=await digest([input.decision,input.reviewId,reasonDigest]);
  const previous=replay(
    await prior(db,input.commissionId,input.actorSubject,input.requestKey),
    input.decision,hash
  );
  if(previous)return previous;
  if(caseRow.status!=="in_review"){
    throw new RecoveryReviewConflictError("Recovery case already decided");
  }
  const status:RecoveryReviewStatus=input.decision==="endorse"
    ?"endorsed_for_operator_review":"dismissed";
  const reviewedAt=new Date().toISOString();
  try{
    const results=await db.batch([
      db.prepare(`
        UPDATE processing_recovery_reviews
        SET status=?,reviewed_by=?,reviewed_at=?,decision_digest=?
        WHERE id=? AND commission_id=? AND status='in_review'
          AND requested_by<>?
          AND EXISTS(
            SELECT 1 FROM commissions c
            JOIN commission_members m ON m.commission_id=c.id
            WHERE c.id=? AND c.status='active'
              AND m.subject=? AND m.active=1 AND m.role IN ('president','member')
          )
          AND (
            ?='dismissed' OR EXISTS(
              SELECT 1 FROM document_versions v
              JOIN documents d ON d.id=v.document_id
              JOIN document_processing_outbox o ON o.document_version_id=v.id
              JOIN commission_members sponsor ON sponsor.commission_id=d.commission_id
              WHERE v.id=processing_recovery_reviews.document_version_id
                AND sponsor.subject=processing_recovery_reviews.requested_by
                AND sponsor.active=1 AND sponsor.role='president'
                AND d.commission_id=processing_recovery_reviews.commission_id
                AND v.sha256=processing_recovery_reviews.source_sha256
                AND v.extraction_status='pending'
                AND o.state='sent' AND o.attempts=10 AND o.last_sent_at IS NOT NULL
                AND NOT EXISTS(
                  SELECT 1 FROM document_processing_reports r
                  WHERE r.document_version_id=v.id
                )
            )
          )
      `).bind(status,input.actorSubject,reviewedAt,reasonDigest,
        input.reviewId,input.commissionId,input.actorSubject,
        input.commissionId,input.actorSubject,status),
      db.prepare(`
        INSERT INTO processing_recovery_actions(
          commission_id,actor_subject,request_key,review_id,action,payload_sha256,result_status
        ) SELECT ?,?,?,?,?,?,? WHERE changes()=1
      `).bind(input.commissionId,input.actorSubject,input.requestKey,
        input.reviewId,input.decision,hash,status),
      db.prepare(`
        INSERT INTO audit_events(
          id,commission_id,actor_subject,action,resource_type,resource_id,metadata_json
        ) SELECT ?,?,?,'processing.recovery_review_decided','recovery_review',?,
          json_object('status',?) WHERE changes()=1
      `).bind(crypto.randomUUID(),input.commissionId,input.actorSubject,
        input.reviewId,status)
    ]);
    requireBatchSuccess(results);
  }catch{
    const concurrent=replay(
      await prior(db,input.commissionId,input.actorSubject,input.requestKey),
      input.decision,hash
    );
    if(concurrent)return concurrent;
    throw new RecoveryReviewConflictError("Recovery review decision stale or invalid");
  }
  return {id:input.reviewId,status,replayed:false};
}
