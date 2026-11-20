import {
  calculateJwkThumbprint,importJWK,jwtVerify,type JWK,type JWTPayload
} from "jose";
import {authenticateAccess,type AccessConfig} from "./access";

/**
 * Isolated R2.8 revocation-operator preflight. There are no active secrets,
 * signers, routes, cron jobs or Queue bindings. A signed MFA assertion is only
 * as trustworthy as the incident authority's separately audited procedures.
 */
export class RevocationAuthorizationError extends Error {}
export type RevocationKind =
  "operator"|"approval_ref"|"attestation"|"image"|"approval_key"|"release_key";
export interface RevocationScope {
  kind:RevocationKind;
  target:string;
  incidentRef:string;
  requestKey:string;
  reason:string;
}
export interface RevocationEvidence {
  actorAccessRequest:Request;
  approverAccessRequest:Request;
  /** An independent incident authority endorses the exact operation. */
  approvalJwt:string;
}
export interface RevocationAuthorizationConfig extends AccessConfig {
  configuredIncidentActorSubject?:string;
  configuredIncidentApproverSubject?:string;
  incidentAuthority?:{
    issuer:string;
    audience:string;
    publicJwk:JWK;
  };
}
const kinds:readonly string[]=[
  "operator","approval_ref","attestation","image","approval_key","release_key"
];
const SUBJECT=/^[\x21-\x7E]{1,200}$/;
const KEY=/^[A-Za-z0-9_-]{8,96}$/;
const INCIDENT=/^INC_[A-Za-z0-9_-]{8,60}$/;
const APPROVAL=/^OPR_[A-Za-z0-9_-]{8,60}$/;
const SHA=/^[0-9a-f]{64}$/;
const IMAGE=/^sha256:[0-9a-f]{64}$/;
const THUMBPRINT=/^[A-Za-z0-9_-]{43}$/;
const MAX_MFA_AGE=300;
const MAX_CLOCK_SKEW=30;
const trustedProofs=new WeakSet<object>();
const revocationBrand:unique symbol=Symbol("approved-redrive-revocation");

export type VerifiedRevocationAuthorization=Readonly<{
  kind:RevocationKind;
  targetHash:string;
  reasonHash:string;
  incidentRef:string;
  requestKey:string;
  actorSubject:string;
  approverSubject:string;
  approvalDigest:string;
  approvalKeyThumbprint:string;
  expiresAt:number;
  readonly [revocationBrand]:true;
}>;

export function validRevocationScope(scope:RevocationScope):boolean {
  if(!scope || !validRevocationTarget(scope.kind,scope.target)
    || !KEY.test(scope.requestKey)
    || !INCIDENT.test(scope.incidentRef)
    || typeof scope.reason!=="string"
    || scope.reason.trim().length<32 || scope.reason.trim().length>600
    || /[\u0000-\u001f\u007f]/.test(scope.reason))return false;
  return true;
}

export function validRevocationTarget(kind:RevocationScope["kind"],target:string):boolean {
  if(!kinds.includes(kind) || typeof target!=="string")return false;
  switch(kind) {
    case "operator":return SUBJECT.test(target);
    case "approval_ref":return APPROVAL.test(target)
      && target.length<=64;
    case "attestation":return SHA.test(target);
    case "image":return IMAGE.test(target);
    case "approval_key":
    case "release_key":return THUMBPRINT.test(target);
  }
}

function validRoot(config:RevocationAuthorizationConfig):boolean {
  const root=config.incidentAuthority;
  if(!root || typeof root.issuer!=="string"
    || typeof root.audience!=="string" || root.audience.length<8
    || !root.publicJwk || typeof root.publicJwk!=="object")return false;
  try {
    const url=new URL(root.issuer);
    const access=new URL(config.ACCESS_TEAM_DOMAIN??"");
    const key=root.publicJwk;
    return url.protocol==="https:" && url.origin===root.issuer
      && url.origin!==access.origin && key.kty==="RSA"
      && typeof key.n==="string" && typeof key.e==="string"
      && [key.d,key.p,key.q,key.dp,key.dq,key.qi].every(part=>part===undefined);
  }catch{return false;}
}
function validActor(value:unknown):value is string {
  return typeof value==="string" && SUBJECT.test(value);
}
function validTimestamp(value:unknown,now:number):value is number {
  return typeof value==="number" && Number.isSafeInteger(value)
    && value<=now+MAX_CLOCK_SKEW && value>=now-MAX_MFA_AGE;
}
async function sha256(content:unknown):Promise<string> {
  const bytes=new TextEncoder().encode(JSON.stringify(content));
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)))
    .map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function binding(scope:RevocationScope):Promise<{
  targetHash:string;reasonHash:string
}>{
  const [targetHash,reasonHash]=await Promise.all([
    sha256([scope.kind,scope.target]),
    sha256(scope.reason.trim())
  ]);
  return {targetHash,reasonHash};
}

export async function isVerifiedRevocationAuthorization(
  value:unknown,expected:RevocationScope & {
    actorSubject:string;approverSubject:string
  }
):Promise<boolean>{
  if(!value || typeof value!=="object" || !trustedProofs.has(value)
    || !validRevocationScope(expected))return false;
  const proof=value as VerifiedRevocationAuthorization;
  if(proof[revocationBrand]!==true || !Number.isFinite(proof.expiresAt)
    || proof.expiresAt<=Date.now() || proof.kind!==expected.kind
    || proof.incidentRef!==expected.incidentRef
    || proof.requestKey!==expected.requestKey
    || proof.actorSubject!==expected.actorSubject
    || proof.approverSubject!==expected.approverSubject
    || !SHA.test(proof.approvalDigest)
    || !THUMBPRINT.test(proof.approvalKeyThumbprint))return false;
  const {targetHash,reasonHash}=await binding(expected);
  return proof.targetHash===targetHash && proof.reasonHash===reasonHash;
}

export async function verifyRevocationAuthorization(
  config:RevocationAuthorizationConfig,
  evidence:RevocationEvidence,
  scope:RevocationScope
):Promise<VerifiedRevocationAuthorization> {
  if(!validRevocationScope(scope)||!validRoot(config)
    || !validActor(config.configuredIncidentActorSubject)
    || !validActor(config.configuredIncidentApproverSubject)
    || config.configuredIncidentActorSubject===config.configuredIncidentApproverSubject){
    throw new RevocationAuthorizationError("Incident revocation authority not configured");
  }
  try {
    const [actorSubject,approverSubject]=await Promise.all([
      authenticateAccess(evidence.actorAccessRequest,config),
      authenticateAccess(evidence.approverAccessRequest,config)
    ]);
    if(!actorSubject || !approverSubject || actorSubject===approverSubject
      || actorSubject!==config.configuredIncidentActorSubject
      || approverSubject!==config.configuredIncidentApproverSubject) {
      throw new Error("Distinct authorized Access principals required");
    }
    const root=config.incidentAuthority!;
    const key=await importJWK(root.publicJwk,"RS256");
    const signed=await jwtVerify(evidence.approvalJwt,key,{
      algorithms:["RS256"],issuer:root.issuer,audience:root.audience,
      maxTokenAge:"5m"
    });
    const payload:JWTPayload=signed.payload;
    const {targetHash,reasonHash}=await binding(scope);
    for(const [name,value] of [
      ["purpose","folio.redrive.revocation.approval.v1"],
      ["kind",scope.kind],["targetHash",targetHash],
      ["reasonHash",reasonHash],["incidentRef",scope.incidentRef],
      ["requestKey",scope.requestKey],["actorSubject",actorSubject],
      ["approverSubject",approverSubject],["decision","approved"]
    ] as const) {
      if(payload[name]!==value)throw new Error("Signed incident scope mismatch");
    }
    const now=Math.floor(Date.now()/1000);
    if(payload.mfa!=="verified" || !validTimestamp(payload.mfaAt,now)
      || !Number.isSafeInteger(payload.iat)
      || !Number.isSafeInteger(payload.exp)
      || payload.sub!==approverSubject
      || payload.exp!<=now || payload.exp!-payload.iat!>MAX_MFA_AGE) {
      throw new Error("Current signed incident approval and MFA required");
    }
    const expiresAt=Math.min(payload.exp!,
      (payload.mfaAt as number)+MAX_MFA_AGE,
      payload.iat!+MAX_MFA_AGE)*1000;
    if(expiresAt<=Date.now())throw new Error("Approval expired");
    const [approvalDigest,approvalKeyThumbprint]=await Promise.all([
      sha256(evidence.approvalJwt),
      calculateJwkThumbprint(root.publicJwk)
    ]);
    const proof=Object.freeze({
      kind:scope.kind,targetHash,reasonHash,
      incidentRef:scope.incidentRef,requestKey:scope.requestKey,
      actorSubject,approverSubject,approvalDigest,approvalKeyThumbprint,
      expiresAt,[revocationBrand]:true as const
    });
    trustedProofs.add(proof);
    return proof;
  }catch{
    // No detail about which authority or subject failed is returned.
    throw new RevocationAuthorizationError("Independent incident approval could not be verified");
  }
}
