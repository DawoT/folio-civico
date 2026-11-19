import {
  validRevocationScope,type RevocationScope,
  signedHash,isVerifiedAsyncIncidentActor,isVerifiedAsyncIncidentDecision,
  type VerifiedAsyncActor,type VerifiedAsyncDecision,type StoredRevocationScope
} from "@folio/auth";

/** An isolated two-session workflow. No network bindings or endpoint here. */
export class AsyncRevocationDenied extends Error {}
export class AsyncRevocationConflict extends Error {}
export type AsyncRevocationResult={
  id:string;status:"pending"|"approved";replayed:boolean
};
export interface PendingRevocation extends StoredRevocationScope {
  status:"pending"|"approved";
  payloadHash:string;
  approverSubject:string|null;
  approvalDigest:string|null;
  approvalKeyThumbprint:string|null;
}
const ID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TTL_SECONDS=86400;

export async function findAsyncRevocation(
  db:D1Database,id:string
):Promise<PendingRevocation|null>{
  if(!ID.test(id))return null;
  return db.prepare(`
    SELECT id,actor_subject AS actorSubject,kind,target,
      target_sha256 AS targetHash,reason_sha256 AS reasonHash,
      incident_ref AS incidentRef,request_key AS requestKey,
      expires_at AS expiresAt,status,payload_sha256 AS payloadHash,
      approver_subject AS approverSubject,approval_sha256 AS approvalDigest,
      approval_key_thumbprint AS approvalKeyThumbprint
    FROM processing_async_revocation_requests WHERE id=?
  `).bind(id).first<PendingRevocation>();
}

export async function proposeAsyncRevocation(
  db:D1Database,scope:RevocationScope,actorProof:VerifiedAsyncActor
):Promise<AsyncRevocationResult>{
  if(!validRevocationScope(scope)||!isVerifiedAsyncIncidentActor(actorProof)){
    throw new AsyncRevocationDenied("A configured actor and valid scope are required");
  }
  const [targetHash,reasonHash]=await Promise.all([
    signedHash([scope.kind,scope.target]),
    signedHash(scope.reason.trim())
  ]);
  const payloadHash=await signedHash([
    actorProof.subject,scope.kind,scope.target,scope.incidentRef,
    scope.requestKey,targetHash,reasonHash
  ]);
  const previous=async()=>{
    return db.prepare(`
      SELECT id,status,payload_sha256 AS payloadHash
      FROM processing_async_revocation_requests
      WHERE actor_subject=? AND request_key=?
    `).bind(actorProof.subject,scope.requestKey)
      .first<{id:string;status:"pending"|"approved";payloadHash:string}>();
  };
  const old=await previous();
  if(old){
    if(old.payloadHash!==payloadHash)throw new AsyncRevocationConflict("Request key already bound");
    return {id:old.id,status:old.status,replayed:true};
  }
  if(!isVerifiedAsyncIncidentActor(actorProof))
    throw new AsyncRevocationDenied("Actor authorization expired");
  const id=crypto.randomUUID();
  try{
    const result=await db.prepare(`
      INSERT INTO processing_async_revocation_requests(
        id,actor_subject,request_key,kind,target,incident_ref,
        target_sha256,reason_sha256,payload_sha256,expires_at
      ) VALUES(?,?,?,?,?,?,?,?,?,unixepoch()+?)
    `).bind(id,actorProof.subject,scope.requestKey,scope.kind,scope.target,
      scope.incidentRef,targetHash,reasonHash,payloadHash,TTL_SECONDS).run();
    if(!result.success||result.meta.changes!==1)throw new Error("Missing proposal");
    return {id,status:"pending",replayed:false};
  }catch{
    const concurrent=await previous();
    if(concurrent?.payloadHash===payloadHash){
      return {id:concurrent.id,status:concurrent.status,replayed:true};
    }
    throw new AsyncRevocationConflict("Incident already proposed or unavailable");
  }
}

export async function approveAsyncRevocation(
  db:D1Database,stored:PendingRevocation,
  decision:VerifiedAsyncDecision
):Promise<Pick<AsyncRevocationResult,"status"|"replayed">>{
  if(!isVerifiedAsyncIncidentDecision(decision,stored)){
    throw new AsyncRevocationDenied("Independent signed approval required");
  }
  if(stored.status==="approved"){
    // A replay is legitimate only with the ORIGINAL approving JWS and identity
    // and with both permanent rows present, not a forged/partial journal.
    const existing=await db.prepare(`
      SELECT 1 AS found FROM processing_redrive_revocation_actions a
      JOIN processing_redrive_revocations r ON r.kind=a.kind AND r.target=a.target
        AND r.incident_ref=a.incident_ref
      WHERE a.actor_subject=? AND a.request_key=? AND a.kind=?
        AND a.target=? AND a.incident_ref=?
        AND a.approver_subject=? AND a.approval_sha256=?
    `).bind(stored.actorSubject,stored.requestKey,stored.kind,
      stored.target,stored.incidentRef,decision.approverSubject,
      decision.approvalDigest).first<{found:number}>();
    if(!existing)throw new AsyncRevocationConflict("Incomplete approval journal");
    return {status:"approved",replayed:true};
  }
  if(stored.expiresAt<=Math.floor(Date.now()/1000))
    throw new AsyncRevocationConflict("Pending incident expired");
  // One atomic D1 transaction: action, denial and authorized decision.
  // No auto Queue send and no user-supplied token persisted.
  try{
    const result=await db.batch([
      db.prepare(`
        INSERT INTO processing_redrive_revocation_actions(
          actor_subject,request_key,kind,target,incident_ref,
          approver_subject,target_sha256,reason_sha256,
          approval_sha256,approval_key_thumbprint,payload_sha256
        )
        SELECT actor_subject,request_key,kind,target,incident_ref,
          ?,target_sha256,reason_sha256,?,?,?
        FROM processing_async_revocation_requests
        WHERE id=? AND status='pending' AND expires_at>unixepoch()
          AND actor_subject<>? AND kind=? AND target_sha256=?
          AND reason_sha256=? AND incident_ref=? AND request_key=?
      `).bind(
        decision.approverSubject,decision.approvalDigest,
        decision.approvalKeyThumbprint,
        await signedHash([
          stored.kind,stored.target,stored.incidentRef,stored.requestKey,
          stored.actorSubject,decision.approverSubject,
          stored.targetHash,stored.reasonHash,decision.approvalDigest,
          decision.approvalKeyThumbprint
        ]),
        stored.id,decision.approverSubject,stored.kind,stored.targetHash,
        stored.reasonHash,stored.incidentRef,stored.requestKey
      ),
      db.prepare(`
        INSERT INTO processing_redrive_revocations(kind,target,incident_ref)
        SELECT kind,target,incident_ref FROM processing_async_revocation_requests
        WHERE id=? AND changes()=1
      `).bind(stored.id),
      db.prepare(`
        UPDATE processing_async_revocation_requests
        SET status='approved',approver_subject=?,approval_sha256=?,
          approval_key_thumbprint=?,decided_at=unixepoch()
        WHERE id=? AND status='pending' AND changes()=1
      `).bind(decision.approverSubject,decision.approvalDigest,
        decision.approvalKeyThumbprint,stored.id)
    ]);
    if(result.length!==3||result.some(x=>!x.success||x.meta.changes!==1))
      throw new Error("Incomplete atomic incident decision");
    return {status:"approved",replayed:false};
  }catch{
    // A racing approval might have committed. Never assume success without
    // a matching immutable incident+denylist and the same approval digest.
    const current=await findAsyncRevocation(db,stored.id);
    if(current?.status==="approved" && current.approverSubject===decision.approverSubject
      && current.approvalDigest===decision.approvalDigest){
      const row=await db.prepare(`
        SELECT 1 AS found FROM processing_redrive_revocation_actions a
        JOIN processing_redrive_revocations r ON a.kind=r.kind AND a.target=r.target
          AND a.incident_ref=r.incident_ref
        WHERE a.actor_subject=? AND a.request_key=? AND a.approval_sha256=?
      `).bind(stored.actorSubject,stored.requestKey,
        decision.approvalDigest).first<{found:number}>();
      if(row)return {status:"approved",replayed:true};
    }
    throw new AsyncRevocationConflict("Incident already decided or unavailable");
  }
}
