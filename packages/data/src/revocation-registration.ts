import {
  isVerifiedRevocationAuthorization,
  type RevocationScope,type VerifiedRevocationAuthorization
} from "@folio/auth";

/** R2.8: isolated, PRIVATE incident response writer. No deployed route/cron. */
export class RevocationRegistrationAccessError extends Error {}
export class RevocationRegistrationConflictError extends Error {}
export type RevocationRegistrationResult=Readonly<{
  registered:true;
  replayed:boolean;
}>;
interface ActionRow {payloadHash:string;confirmed:number}

async function hash(parts:unknown):Promise<string> {
  const bytes=new TextEncoder().encode(JSON.stringify(parts));
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)))
    .map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function prior(db:D1Database,actor:string,requestKey:string)
:Promise<ActionRow|null> {
  return db.prepare(`
    SELECT a.payload_sha256 AS payloadHash,
      CASE WHEN r.kind IS NULL THEN 0 ELSE 1 END AS confirmed
    FROM processing_redrive_revocation_actions a
    LEFT JOIN processing_redrive_revocations r ON r.kind=a.kind
      AND r.target=a.target AND r.incident_ref=a.incident_ref
    WHERE a.actor_subject=? AND a.request_key=?
  `).bind(actor,requestKey).first<ActionRow>();
}
async function requireAuthorization(scope:RevocationScope,
  proof:VerifiedRevocationAuthorization|undefined):Promise<VerifiedRevocationAuthorization> {
  if(!proof || !await isVerifiedRevocationAuthorization(proof,{
    ...scope,actorSubject:proof.actorSubject,approverSubject:proof.approverSubject
  })) {
    throw new RevocationRegistrationAccessError("Valid independent incident approval required");
  }
  return proof;
}

/**
 * One atomic journal+denylist append. This code MUST ONLY be called by an
 * approved private host which supplies Access requests and a signed incident
 * decision via the verifier. Signer approval procedures and D1 write controls
 * are separate external security gates, not supplied by this package.
 *
 * Neither a failed D1 transaction nor replay ever calls Queue or R2.
 */
export async function registerRedriveRevocation(
  db:D1Database,scope:RevocationScope,
  authorization:VerifiedRevocationAuthorization|undefined
):Promise<RevocationRegistrationResult> {
  const proof=await requireAuthorization(scope,authorization);
  const payloadHash=await hash([
    scope.kind,scope.target,scope.incidentRef,scope.requestKey,
    proof.actorSubject,proof.approverSubject,
    proof.targetHash,proof.reasonHash,
    proof.approvalDigest,proof.approvalKeyThumbprint
  ]);
  const previous=await prior(db,proof.actorSubject,scope.requestKey);
  if(previous) {
    if(previous.payloadHash!==payloadHash || previous.confirmed!==1){
      throw new RevocationRegistrationConflictError("Incident request key already used");
    }
    return {registered:true,replayed:true};
  }
  // Time may advance between the first validation and D1 reads.
  await requireAuthorization(scope,authorization);
  try{
    const changes=await db.batch([
      db.prepare(`
        INSERT INTO processing_redrive_revocation_actions(
          actor_subject,request_key,kind,target,incident_ref,
          approver_subject,target_sha256,reason_sha256,
          approval_sha256,approval_key_thumbprint,payload_sha256
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
      `).bind(proof.actorSubject,scope.requestKey,scope.kind,
        scope.target,scope.incidentRef,proof.approverSubject,
        proof.targetHash,proof.reasonHash,proof.approvalDigest,
        proof.approvalKeyThumbprint,payloadHash),
      db.prepare(`
        INSERT INTO processing_redrive_revocations(kind,target,incident_ref)
        SELECT ?,?,? WHERE changes()=1
      `).bind(scope.kind,scope.target,scope.incidentRef)
    ]);
    if(changes.length!==2 || changes.some(x=>!x.success||x.meta.changes!==1)) {
      throw new Error("Incomplete revocation registration transaction");
    }
  }catch{
    // D1 batch is atomic: a competing append may have won the unique key.
    // A failed/ambiguous batch must never return success without its journal.
    let concurrent:ActionRow|null=null;
    try{
      concurrent=await prior(db,proof.actorSubject,scope.requestKey);
    }catch{
      throw new RevocationRegistrationConflictError("Revocation registration unavailable");
    }
    if(concurrent?.payloadHash===payloadHash && concurrent.confirmed===1) {
      // Only accept replay when BOTH immutable rows are present.
      const match=await db.prepare(`
        SELECT 1 AS found FROM processing_redrive_revocations
        WHERE kind=? AND target=? AND incident_ref=?
      `).bind(scope.kind,scope.target,scope.incidentRef).first<{found:number}>();
      if(match)return {registered:true,replayed:true};
    }
    throw new RevocationRegistrationConflictError("Revocation already exists or transaction failed");
  }
  return {registered:true,replayed:false};
}
