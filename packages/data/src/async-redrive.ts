import {
  isVerifiedAsyncRedriveRequester,isVerifiedAsyncRedriveDecision,
  validOneShotRedriveScope,type OneShotAuthorizationScope,
  type StoredAsyncRedrive,type VerifiedAsyncRedriveRequester,
  type VerifiedAsyncRedriveDecision
} from "@folio/auth";
import {areOperatorSubjectsRevoked} from "./async-authority-guards";
import {matchesInstitutionalEvidence,type InstitutionalEvidenceReceipt} from "./institutional-approval-journal";

/** Global private D1 operation: no Worker routes, secrets, or remote host. */
export class AsyncRedriveAccessError extends Error {}
export class AsyncRedriveConflictError extends Error {}
export type PendingRedrive=StoredAsyncRedrive & {
  status:"pending"|"approved";
  approverSubject:string|null;
  approvalDigest:string|null;
  approvalKeyThumbprint:string|null;
  institutionalGateRequired:number;
};
export type ProposalResult=Readonly<{
  id:string;status:"pending"|"approved";replayed:boolean;
}>;
export type DecisionResult=Readonly<{status:"approved";replayed:boolean}>;
const ID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TTL=24*60*60;

/** Revocation of the independent approver takes effect even after signing. */
export async function isAsyncRedriveApproverRevoked(
  db:D1Database,id:string
):Promise<boolean>{
  const blocked=await db.prepare(`
    SELECT 1 AS blocked
    FROM processing_async_redrive_requests p
    JOIN processing_redrive_revocations r
      ON r.kind='operator' AND r.target=p.approver_subject
    WHERE p.id=? LIMIT 1
  `).bind(id).first<{blocked:number}>();
  return blocked!==null;
}
export async function findAsyncRedrive(
  db:D1Database,id:string
):Promise<PendingRedrive|null>{
  if(!ID.test(id))return null;
  return db.prepare(`
    SELECT id,operator_subject AS operatorSubject,commission_id AS commissionId,
      recovery_review_id AS reviewId,request_key AS requestKey,
      approval_ref AS approvalRef,expires_at AS expiresAt,status,
      approver_subject AS approverSubject,approval_sha256 AS approvalDigest,
      approval_key_thumbprint AS approvalKeyThumbprint,
      institutional_gate_required AS institutionalGateRequired
    FROM processing_async_redrive_requests
    WHERE id=?
  `).bind(id).first<PendingRedrive>();
}
export async function proposeAsyncRedrive(
  db:D1Database,scope:OneShotAuthorizationScope,
  operator:VerifiedAsyncRedriveRequester,institutionalGateRequired=false
):Promise<ProposalResult>{
  if(!validOneShotRedriveScope(scope)||!isVerifiedAsyncRedriveRequester(operator)){
    throw new AsyncRedriveAccessError("Verified operator and valid recovery scope required");
  }
  if(await areOperatorSubjectsRevoked(db,operator.subject)){
    throw new AsyncRedriveAccessError("Operator authority withdrawn");
  }
  const prior=async()=>db.prepare(`
    SELECT id,status,commission_id AS commissionId,recovery_review_id AS reviewId,
      approval_ref AS approvalRef,expires_at AS expiresAt,
      institutional_gate_required AS institutionalGateRequired
    FROM processing_async_redrive_requests
    WHERE operator_subject=? AND request_key=?
  `).bind(operator.subject,scope.requestKey).first<{
    id:string;status:"pending"|"approved";commissionId:string;
    reviewId:string;approvalRef:string;expiresAt:number;institutionalGateRequired:number
  }>();
  const old=await prior();
  if(old){
    if(old.commissionId!==scope.commissionId || old.reviewId!==scope.reviewId
      || old.approvalRef!==scope.approvalRef
      || Boolean(old.institutionalGateRequired)!==institutionalGateRequired
      || old.expiresAt<=Math.floor(Date.now()/1000)){
      throw new AsyncRedriveConflictError("Proposal key already used or expired");
    }
    return {id:old.id,status:old.status,replayed:true};
  }
  if(!isVerifiedAsyncRedriveRequester(operator))
    throw new AsyncRedriveAccessError("Operator capability expired");
  const id=crypto.randomUUID();
  try{
    const result=await db.prepare(`
      INSERT INTO processing_async_redrive_requests(
        id,commission_id,recovery_review_id,operator_subject,request_key,
        approval_ref,expires_at,institutional_gate_required
      ) VALUES(?,?,?,?,?,?,unixepoch()+?,?)
    `).bind(id,scope.commissionId,scope.reviewId,operator.subject,
      scope.requestKey,scope.approvalRef,TTL,institutionalGateRequired?1:0).run();
    if(!result.success || result.meta.changes!==1)throw new Error("No proposal recorded");
    return {id,status:"pending",replayed:false};
  }catch{
    const concurrent=await prior();
    if(concurrent && concurrent.commissionId===scope.commissionId
      && concurrent.reviewId===scope.reviewId
      && concurrent.approvalRef===scope.approvalRef
      && Boolean(concurrent.institutionalGateRequired)===institutionalGateRequired){
      return {id:concurrent.id,status:concurrent.status,replayed:true};
    }
    throw new AsyncRedriveConflictError("Proposal already exists or D1 unavailable");
  }
}

async function sameApproval(db:D1Database,stored:PendingRedrive,
  decision:VerifiedAsyncRedriveDecision):Promise<boolean>{
  const exists=await db.prepare(`
    SELECT 1 AS found FROM processing_async_redrive_approvals a
    JOIN processing_async_redrive_requests p ON p.id=a.request_id
    WHERE a.request_id=? AND p.status='approved'
      AND p.operator_subject=a.operator_subject
      AND p.approver_subject=a.approver_subject
      AND p.approval_sha256=a.approval_sha256
      AND p.approval_key_thumbprint=a.approval_key_thumbprint
      AND p.operator_subject=? AND a.approver_subject=?
      AND a.approval_sha256=? AND a.approval_key_thumbprint=?
  `).bind(stored.id,stored.operatorSubject,decision.approverSubject,
    decision.approvalDigest,decision.approvalKeyThumbprint).first<{found:number}>();
  return !!exists;
}
export async function approveAsyncRedrive(
  db:D1Database,stored:PendingRedrive,decision:VerifiedAsyncRedriveDecision,
  evidence?:InstitutionalEvidenceReceipt
):Promise<DecisionResult>{
  if(!isVerifiedAsyncRedriveDecision(decision,stored)){
    throw new AsyncRedriveAccessError("Independent signed redrive approver required");
  }
  if(stored.institutionalGateRequired && !evidence){
    throw new AsyncRedriveAccessError("Institutional receipt required");
  }
  if(await areOperatorSubjectsRevoked(db,stored.operatorSubject,decision.approverSubject)){
    throw new AsyncRedriveAccessError("Redrive approval authority withdrawn");
  }
  if(stored.status==="approved"){
    if(await sameApproval(db,stored,decision)
      && (!evidence || await matchesInstitutionalEvidence(
        db,"redrive",stored.id,stored.operatorSubject,
        decision.approverSubject,decision.approvalDigest,stored.expiresAt,evidence
      )))return {status:"approved",replayed:true};
    throw new AsyncRedriveConflictError("Different approval already recorded");
  }
  if(stored.expiresAt<=Math.floor(Date.now()/1000))
    throw new AsyncRedriveConflictError("Proposal has expired");
  try{
    const results=await db.batch([
      db.prepare(`
        INSERT INTO processing_async_redrive_approvals(
          request_id,operator_subject,approver_subject,
          approval_sha256,approval_key_thumbprint
        ) SELECT id,operator_subject,?,?,?
          FROM processing_async_redrive_requests
          WHERE id=? AND status='pending' AND expires_at>unixepoch()
            AND operator_subject<>?
      `).bind(decision.approverSubject,decision.approvalDigest,
        decision.approvalKeyThumbprint,stored.id,decision.approverSubject),
      ...(evidence?[db.prepare(`
        INSERT INTO processing_institutional_approval_evidence(
          purpose,request_id,actor_subject,approver_subject,scope_sha256,
          approval_sha256,case_revision,checked_at,expires_at
        ) SELECT 'redrive',id,operator_subject,?,?,?,?,?,expires_at
        FROM processing_async_redrive_requests
        WHERE id=? AND status='pending'
      `).bind(decision.approverSubject,evidence.scopeDigest,
        decision.approvalDigest,evidence.caseRevision,evidence.checkedAt,stored.id)]:[]),
      db.prepare(`
        UPDATE processing_async_redrive_requests
        SET status='approved',approver_subject=?,approval_sha256=?,
          approval_key_thumbprint=?,approved_at=unixepoch()
        WHERE id=? AND status='pending' AND expires_at>unixepoch()
          AND changes()=1
      `).bind(decision.approverSubject,decision.approvalDigest,
        decision.approvalKeyThumbprint,stored.id)
    ]);
    if(results.length!==(evidence?3:2)
      || results.some(r=>!r.success||r.meta.changes!==1)){
      throw new Error("Incomplete independent redrive approval");
    }
    return {status:"approved",replayed:false};
  }catch{
    const current=await findAsyncRedrive(db,stored.id);
    if(current && await sameApproval(db,current,decision)
      && (!evidence || await matchesInstitutionalEvidence(
        db,"redrive",stored.id,stored.operatorSubject,
        decision.approverSubject,decision.approvalDigest,stored.expiresAt,evidence
      ))){
      return {status:"approved",replayed:true};
    }
    throw new AsyncRedriveConflictError("Redrive approval already decided or unavailable");
  }
}
