import {calculateJwkThumbprint,importJWK,jwtVerify,type JWTPayload} from "jose";
import {authenticateAccess} from "./access";
import {
  validRevocationTarget,type RevocationScope,type RevocationAuthorizationConfig
} from "./revocation-authorization";

/**
 * R2.10: two independent, time-separated Access sessions. No Access token
 * from one person is ever forwarded to or consumed by the other's request.
 * This verifies claims, not the real-world MFA/incident authority procedure.
 */
export class AsyncRevocationAccessError extends Error {}
export interface StoredRevocationScope {
  id:string;
  actorSubject:string;
  kind:RevocationScope["kind"];
  target:string;
  targetHash:string;
  reasonHash:string;
  incidentRef:string;
  requestKey:string;
  expiresAt:number;
}
const actorProofs=new WeakSet<object>();
const approverProofs=new WeakSet<object>();
const decisionProofs=new WeakSet<object>();
const actorBrand:unique symbol=Symbol("async-incident-actor");
const approverBrand:unique symbol=Symbol("async-incident-approver");
const decisionBrand:unique symbol=Symbol("async-incident-decision");
const SHA=/^[a-f0-9]{64}$/;
const THUMBPRINT=/^[A-Za-z0-9_-]{43}$/;
const MAX_AGE=300;
const MAX_SKEW=30;
export type VerifiedAsyncActor=Readonly<{
  subject:string;
  expiresAt:number;
  readonly [actorBrand]:true;
}>;
export type VerifiedAsyncApprover=Readonly<{
  subject:string;
  expiresAt:number;
  readonly [approverBrand]:true;
}>;
export type VerifiedAsyncDecision=Readonly<{
  requestId:string;
  actorSubject:string;
  approverSubject:string;
  kind:RevocationScope["kind"];
  targetHash:string;
  reasonHash:string;
  incidentRef:string;
  requestKey:string;
  approvalDigest:string;
  approvalKeyThumbprint:string;
  expiresAt:number;
  readonly [decisionBrand]:true;
}>;

export async function signedHash(value:unknown):Promise<string>{
  const bytes=new TextEncoder().encode(JSON.stringify(value));
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))]
    .map(b=>b.toString(16).padStart(2,"0")).join("");
}

function configured(config:RevocationAuthorizationConfig):boolean {
  const root=config.incidentAuthority;
  try {
    const u=new URL(root?.issuer??"");
    const a=new URL(config.ACCESS_TEAM_DOMAIN??"");
    const key=root?.publicJwk;
    return !!root && !!key && u.protocol==="https:" && u.origin===root.issuer
      && u.origin!==a.origin && root.audience.length>=8
      && key.kty==="RSA" && typeof key.n==="string"
      && typeof key.e==="string"
      && [key.d,key.p,key.q,key.dp,key.dq,key.qi].every(x=>x===undefined)
      && typeof config.configuredIncidentActorSubject==="string"
      && typeof config.configuredIncidentApproverSubject==="string"
      && !!config.configuredIncidentActorSubject
      && !!config.configuredIncidentApproverSubject
      && config.configuredIncidentActorSubject!==config.configuredIncidentApproverSubject;
  }catch{return false;}
}

export async function verifyAsyncIncidentActor(
  config:RevocationAuthorizationConfig,request:Request
):Promise<VerifiedAsyncActor>{
  if(!configured(config))throw new AsyncRevocationAccessError("Independent incident actor not configured");
  try {
    const subject=await authenticateAccess(request,config);
    if(!subject || subject!==config.configuredIncidentActorSubject){
      throw new Error("Unconfigured Access actor");
    }
    const proof=Object.freeze({subject,expiresAt:Date.now()+120000,[actorBrand]:true as const});
    actorProofs.add(proof);
    return proof;
  }catch{throw new AsyncRevocationAccessError("Actor Access assertion invalid");}
}
export function isVerifiedAsyncIncidentActor(
  value:unknown
):value is VerifiedAsyncActor {
  return !!value && typeof value==="object"
    && actorProofs.has(value) && (value as VerifiedAsyncActor)[actorBrand]===true
    && (value as VerifiedAsyncActor).expiresAt>Date.now();
}

export async function verifyAsyncIncidentApprover(
  config:RevocationAuthorizationConfig,request:Request
):Promise<VerifiedAsyncApprover>{
  if(!configured(config))throw new AsyncRevocationAccessError("Independent approver not configured");
  try {
    const subject=await authenticateAccess(request,config);
    if(!subject || subject!==config.configuredIncidentApproverSubject){
      throw new Error("Unconfigured Access approver");
    }
    const proof=Object.freeze({subject,expiresAt:Date.now()+120000,[approverBrand]:true as const});
    approverProofs.add(proof);
    return proof;
  }catch{throw new AsyncRevocationAccessError("Approver Access assertion invalid");}
}

export async function verifyAsyncIncidentDecision(
  config:RevocationAuthorizationConfig,approverProof:VerifiedAsyncApprover,
  signedApproval:string,stored:StoredRevocationScope
):Promise<VerifiedAsyncDecision>{
  if(!configured(config)||!stored || !approverProof
    || !approverProofs.has(approverProof) || approverProof[approverBrand]!==true
    || approverProof.expiresAt<=Date.now()
    || !SHA.test(stored.targetHash)
    || !SHA.test(stored.reasonHash) || stored.expiresAt*1000<=Date.now()
    || !validRevocationTarget(stored.kind,stored.target)
    || typeof signedApproval!=="string") {
    throw new AsyncRevocationAccessError("Independent incident approval not configured");
  }
  try {
    // The approver independently verified their own Access JWT upstream.
    const approver=approverProof.subject;
    if(!approver || approver!==config.configuredIncidentApproverSubject
      || approver===stored.actorSubject
      || stored.actorSubject!==config.configuredIncidentActorSubject){
      throw new Error("Distinct configured approver required");
    }
    const root=config.incidentAuthority!;
    const key=await importJWK(root.publicJwk,"RS256");
    const {payload}=await jwtVerify(signedApproval,key,{
      algorithms:["RS256"],issuer:root.issuer,audience:root.audience,
      maxTokenAge:"5m"
    });
    const claims:JWTPayload=payload;
    for(const [name,expected] of [
      ["purpose","folio.redrive.revocation.approval.v1"],
      ["kind",stored.kind],["targetHash",stored.targetHash],
      ["reasonHash",stored.reasonHash],["incidentRef",stored.incidentRef],
      ["requestKey",stored.requestKey],["actorSubject",stored.actorSubject],
      ["approverSubject",approver],["decision","approved"]
    ] as const){
      if(claims[name]!==expected)throw new Error("Operation scope does not match");
    }
    const now=Math.floor(Date.now()/1000);
    if(claims.mfa!=="verified" || claims.sub!==approver
      || typeof claims.mfaAt!=="number" || !Number.isSafeInteger(claims.mfaAt)
      || claims.mfaAt<now-MAX_AGE || claims.mfaAt>now+MAX_SKEW
      || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)
      || claims.iat!>now+MAX_SKEW || claims.exp!<=now
      || claims.exp!<=claims.iat! || claims.exp!-claims.iat!>MAX_AGE) {
      throw new Error("MFA confirmation or approval is expired");
    }
    const expiresAt=Math.min(
      claims.exp!,claims.iat!+MAX_AGE,claims.mfaAt+MAX_AGE,
      stored.expiresAt
    )*1000;
    if(expiresAt<=Date.now())throw new Error("Expired decision");
    const [approvalDigest,approvalKeyThumbprint]=await Promise.all([
      signedHash(signedApproval),calculateJwkThumbprint(root.publicJwk)
    ]);
    const proof=Object.freeze({
      requestId:stored.id,actorSubject:stored.actorSubject,
      approverSubject:approver,kind:stored.kind,
      targetHash:stored.targetHash,reasonHash:stored.reasonHash,
      incidentRef:stored.incidentRef,requestKey:stored.requestKey,
      approvalDigest,approvalKeyThumbprint,expiresAt,
      [decisionBrand]:true as const
    });
    decisionProofs.add(proof);
    return proof;
  }catch{
    throw new AsyncRevocationAccessError("Independent signed approval failed verification");
  }
}

export function isVerifiedAsyncIncidentDecision(
  proof:unknown,stored:StoredRevocationScope
):proof is VerifiedAsyncDecision {
  if(!proof || typeof proof!=="object" || !decisionProofs.has(proof))return false;
  const p=proof as VerifiedAsyncDecision;
  return p[decisionBrand]===true && p.expiresAt>Date.now()
    && p.requestId===stored.id && p.actorSubject===stored.actorSubject
    && p.kind===stored.kind && p.targetHash===stored.targetHash
    && p.reasonHash===stored.reasonHash && p.incidentRef===stored.incidentRef
    && p.requestKey===stored.requestKey
    && p.approverSubject!==p.actorSubject
    && SHA.test(p.approvalDigest) && THUMBPRINT.test(p.approvalKeyThumbprint);
}
