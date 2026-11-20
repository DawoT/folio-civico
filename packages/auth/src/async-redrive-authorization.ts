import {authenticateAccess} from "./access";
import {calculateJwkThumbprint,importJWK,jwtVerify} from "jose";
import {
  OperatorAuthorizationError,type OperatorPreflightConfig,
  type OneShotAuthorizationScope
} from "./manual-redrive-authorization";

/** R2.11: independent Access sessions; synthetic-only private adapter. */
const requesterProofs=new WeakSet<object>();
const decisionProofs=new WeakSet<object>();
const requesterBrand:unique symbol=Symbol("async-redrive-requester");
const decisionBrand:unique symbol=Symbol("async-redrive-approver");
const ID=/^[A-Za-z0-9_-]{1,64}$/;
const KEY=/^[A-Za-z0-9_-]{8,96}$/;
const REF=/^OPR_[A-Za-z0-9_-]{8,60}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_MFA_AGE=300;
const CLOCK_SKEW=30;
export interface StoredAsyncRedrive {
  id:string;
  operatorSubject:string;
  commissionId:string;
  reviewId:string;
  requestKey:string;
  approvalRef:string;
  expiresAt:number;
}
export type VerifiedAsyncRedriveRequester=Readonly<{
  subject:string;
  expiresAt:number;
  readonly [requesterBrand]:true;
}>;
export type VerifiedAsyncRedriveDecision=Readonly<{
  requestId:string;
  operatorSubject:string;
  approverSubject:string;
  approvalDigest:string;
  approvalKeyThumbprint:string;
  expiresAt:number;
  readonly [decisionBrand]:true;
}>;

export function validOneShotRedriveScope(scope:OneShotAuthorizationScope):boolean {
  return !!scope
    && ID.test(scope.commissionId) && ID.test(scope.reviewId)
    && KEY.test(scope.requestKey) && REF.test(scope.approvalRef);
}
function validRoot(config:OperatorPreflightConfig):boolean {
  const root=config.approvalAuthority;
  const release=config.releaseAuthority;
  try {
    const issuer=new URL(root?.issuer??"");
    const access=new URL(config.ACCESS_TEAM_DOMAIN??"");
    const key=root?.publicJwk;
    const releaseIssuer=new URL(release?.issuer??"");
    return issuer.protocol==="https:" && issuer.origin===root?.issuer
      && issuer.origin!==access.origin && issuer.origin!==releaseIssuer.origin
      && !!root && root.audience.length>=8
      && !!key && key.kty==="RSA"
      && typeof key.n==="string" && typeof key.e==="string"
      && [key.d,key.p,key.q,key.dp,key.dq,key.qi].every(x=>x===undefined)
      && typeof config.configuredOperatorSubject==="string"
      && typeof config.configuredRedriveApproverSubject==="string"
      && !!config.configuredOperatorSubject && !!config.configuredRedriveApproverSubject
      && config.configuredOperatorSubject!==config.configuredRedriveApproverSubject;
  }catch{return false;}
}
async function sha256(token:string):Promise<string>{
  const bytes=new TextEncoder().encode(JSON.stringify(token));
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))]
    .map(b=>b.toString(16).padStart(2,"0")).join("");
}

export async function verifyAsyncRedriveRequester(
  config:OperatorPreflightConfig,request:Request
):Promise<VerifiedAsyncRedriveRequester>{
  if(!validRoot(config))throw new OperatorAuthorizationError("Redrive operator trust not configured");
  try{
    const subject=await authenticateAccess(request,config);
    if(!subject || subject!==config.configuredOperatorSubject){
      throw new Error("Unknown operator");
    }
    const proof=Object.freeze({
      subject,expiresAt:Date.now()+120000,[requesterBrand]:true as const
    });
    requesterProofs.add(proof);
    return proof;
  }catch{
    throw new OperatorAuthorizationError("Independent redrive operator verification failed");
  }
}
export function isVerifiedAsyncRedriveRequester(
  value:unknown
):value is VerifiedAsyncRedriveRequester{
  return !!value && typeof value==="object"
    && requesterProofs.has(value)
    && (value as VerifiedAsyncRedriveRequester)[requesterBrand]===true
    && (value as VerifiedAsyncRedriveRequester).expiresAt>Date.now();
}

export async function verifyAsyncRedriveDecision(
  config:OperatorPreflightConfig,request:Request,
  approvalJwt:string,stored:StoredAsyncRedrive
):Promise<VerifiedAsyncRedriveDecision>{
  if(!validRoot(config)||!stored || !UUID.test(stored.id)
    || !validOneShotRedriveScope(stored)
    || stored.operatorSubject!==config.configuredOperatorSubject
    || !Number.isSafeInteger(stored.expiresAt)
    || stored.expiresAt*1000<=Date.now()
    || typeof approvalJwt!=="string" || approvalJwt.length>8192){
    throw new OperatorAuthorizationError("Redrive approval not configured or expired");
  }
  try{
    // Only the approver JWT belongs to this request. No operator JWT exists
    // here, nor is either Access assertion stored in the database.
    const approver=await authenticateAccess(request,config);
    if(!approver || approver!==config.configuredRedriveApproverSubject
      || approver===stored.operatorSubject){
      throw new Error("Distinct configured approver required");
    }
    const root=config.approvalAuthority!;
    const key=await importJWK(root.publicJwk,"RS256");
    const {payload}=await jwtVerify(approvalJwt,key,{
      algorithms:["RS256"],issuer:root.issuer,audience:root.audience,
      maxTokenAge:"5m"
    });
    for(const [name,expected] of [
      ["purpose","folio.manual-redrive.approval.v1"],
      ["commissionId",stored.commissionId],["reviewId",stored.reviewId],
      ["requestKey",stored.requestKey],["approvalRef",stored.approvalRef],
      ["proposalId",stored.id],["operatorSubject",stored.operatorSubject],
      ["approverSubject",approver],["sub",approver],["decision","approved"]
    ] as const) {
      if(payload[name]!==expected)throw new Error("Wrong signed approval scope");
    }
    const now=Math.floor(Date.now()/1000);
    if(payload.mfa!=="verified" || !Number.isSafeInteger(payload.mfaAt)
      || typeof payload.mfaAt!=="number"
      || payload.mfaAt<now-MAX_MFA_AGE || payload.mfaAt>now+CLOCK_SKEW
      || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)
      || payload.iat!>now+CLOCK_SKEW || payload.exp!<=now
      || payload.exp!<=payload.iat! || payload.exp!-payload.iat!>MAX_MFA_AGE){
      throw new Error("Signed MFA approval expired or invalid");
    }
    const expiresAt=Math.min(
      payload.exp!,payload.iat!+MAX_MFA_AGE,
      payload.mfaAt+MAX_MFA_AGE,stored.expiresAt
    )*1000;
    if(expiresAt<=Date.now())throw new Error("Decision expired");
    const [approvalDigest,approvalKeyThumbprint]=await Promise.all([
      sha256(approvalJwt),calculateJwkThumbprint(root.publicJwk)
    ]);
    const proof=Object.freeze({
      requestId:stored.id,operatorSubject:stored.operatorSubject,
      approverSubject:approver,approvalDigest,approvalKeyThumbprint,
      expiresAt,[decisionBrand]:true as const
    });
    decisionProofs.add(proof);
    return proof;
  }catch{
    throw new OperatorAuthorizationError("Independent redrive approval could not be verified");
  }
}
export function isVerifiedAsyncRedriveDecision(
  value:unknown,stored:StoredAsyncRedrive
):value is VerifiedAsyncRedriveDecision{
  if(!value || typeof value!=="object" || !decisionProofs.has(value))return false;
  const proof=value as VerifiedAsyncRedriveDecision;
  return proof[decisionBrand]===true && proof.expiresAt>Date.now()
    && proof.requestId===stored.id && proof.operatorSubject===stored.operatorSubject
    && proof.approverSubject!==proof.operatorSubject
    && /^[a-f0-9]{64}$/.test(proof.approvalDigest)
    && /^[A-Za-z0-9_-]{43}$/.test(proof.approvalKeyThumbprint);
}
