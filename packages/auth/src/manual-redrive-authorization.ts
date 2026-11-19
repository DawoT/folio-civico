import {
  calculateJwkThumbprint,importJWK,jwtVerify,type JWK,type JWTPayload
} from "jose";
import {authenticateAccess,type AccessConfig} from "./access";

/**
 * R2.6. This is an offline-only preflight verifier; no handler, endpoint,
 * Worker binding, key material or release credentials are provisioned here.
 *
 * Attestations assert claims made by independently trusted signers. A signed
 * assertion is NOT evidence the signer actually ran Trivy, checked signatures,
 * or verified MFA. Those issuer procedures must be audited separately.
 */
export class OperatorAuthorizationError extends Error {}

export interface SignedTrustRoot {
  issuer:string;
  audience:string;
  publicJwk:JWK;
}
export interface OperatorPreflightConfig extends AccessConfig {
  configuredOperatorSubject?:string;
  approvalAuthority?:SignedTrustRoot;
  releaseAuthority?:SignedTrustRoot;
  /** SHA-256 of the specifically approved inspector image in the trusted host. */
  requiredImageDigest?:string;
}
export interface OneShotAuthorizationScope {
  commissionId:string;
  reviewId:string;
  requestKey:string;
  approvalRef:string;
}
export interface OneShotAuthorizationEvidence {
  /** Verified by Cloudflare Access JWKS. */
  accessRequest:Request;
  /** Separate, operation-bound approval attesting a recent MFA event. */
  approvalJwt:string;
  /** Different signer's attestation of the pinned inspector image release. */
  releaseJwt:string;
}

const ID=/^[A-Za-z0-9_-]{1,64}$/;
const KEY=/^[A-Za-z0-9_-]{8,96}$/;
const APPROVAL=/^OPR_[A-Za-z0-9_-]{8,60}$/;
const IMAGE=/^sha256:[a-f0-9]{64}$/;
const SHA=/^[a-f0-9]{64}$/;
const MAX_MFA_AGE_SECONDS=300;
const MAX_CLOCK_SKEW_SECONDS=30;
const signedProofs=new WeakSet<object>();
const proofBrand:unique symbol=Symbol("verified-operator-redrive");

export type VerifiedRedriveAuthorization=Readonly<{
  operatorSubject:string;
  commissionId:string;
  reviewId:string;
  requestKey:string;
  approvalRef:string;
  imageDigest:string;
  attestationDigest:string;
  expiresAt:number;
  readonly [proofBrand]:true;
}>;

function validRoot(root:SignedTrustRoot|undefined):root is SignedTrustRoot {
  if(!root || !root.publicJwk || typeof root.publicJwk!=="object")return false;
  const {issuer,audience,publicJwk}=root;
  try {
    const url=new URL(issuer);
    return url.protocol==="https:" && url.origin===issuer
      && typeof audience==="string" && audience.length>=8
      && publicJwk.kty==="RSA"
      && typeof publicJwk.n==="string" && typeof publicJwk.e==="string"
      && publicJwk.d===undefined;
  }catch{return false;}
}

function mustMatch(payload:JWTPayload,name:string,value:string):void {
  if(payload[name]!==value)throw new OperatorAuthorizationError("Signed authorization scope mismatch");
}

function recentTimestamp(value:unknown,now:number,age:number):boolean {
  return Number.isSafeInteger(value)
    && typeof value==="number"
    && value<=now+MAX_CLOCK_SKEW_SECONDS
    && value>=now-age;
}

/** Only values issued by this module can pass the runtime WeakSet gate. */
export function isVerifiedRedriveAuthorization(
  value:unknown,expected:{
    operatorSubject:string;commissionId:string;reviewId:string;
    requestKey:string;approvalRef:string;imageDigest:string
  }
):value is VerifiedRedriveAuthorization {
  if(!value || typeof value!=="object" || !signedProofs.has(value))return false;
  const auth=value as VerifiedRedriveAuthorization;
  return auth[proofBrand]===true && Number.isFinite(auth.expiresAt)
    && auth.expiresAt>Date.now()
    && auth.operatorSubject===expected.operatorSubject
    && auth.commissionId===expected.commissionId
    && auth.reviewId===expected.reviewId
    && auth.requestKey===expected.requestKey
    && auth.approvalRef===expected.approvalRef
    && auth.imageDigest===expected.imageDigest
    && /^[a-f0-9]{64}$/.test(auth.attestationDigest);
}

export async function verifyOneShotOperatorAuthorization(
  config:OperatorPreflightConfig,evidence:OneShotAuthorizationEvidence,
  scope:OneShotAuthorizationScope
):Promise<VerifiedRedriveAuthorization> {
  const requiredDigest=config.requiredImageDigest;
  if(!ID.test(scope.commissionId)||!ID.test(scope.reviewId)
    || !KEY.test(scope.requestKey)||!APPROVAL.test(scope.approvalRef)
    || !validRoot(config.approvalAuthority)||!validRoot(config.releaseAuthority)
    || !requiredDigest || !IMAGE.test(requiredDigest)
    || config.approvalAuthority.issuer===config.releaseAuthority.issuer
    || config.approvalAuthority.audience===config.releaseAuthority.audience
    || typeof config.configuredOperatorSubject!=="string") {
    throw new OperatorAuthorizationError("Operator trust roots or operation scope not configured");
  }
  try {
    const [approvalThumbprint,releaseThumbprint]=await Promise.all([
      calculateJwkThumbprint(config.approvalAuthority.publicJwk),
      calculateJwkThumbprint(config.releaseAuthority.publicJwk)
    ]);
    if(approvalThumbprint===releaseThumbprint){
      throw new OperatorAuthorizationError("Independent trust roots required");
    }
    const operatorSubject=await authenticateAccess(evidence.accessRequest,config);
    if(!operatorSubject || operatorSubject!==config.configuredOperatorSubject) {
      throw new OperatorAuthorizationError("Valid configured Access operator required");
    }

    const [approvalKey,releaseKey]=await Promise.all([
      importJWK(config.approvalAuthority.publicJwk,"RS256"),
      importJWK(config.releaseAuthority.publicJwk,"RS256")
    ]);
    const [approval,release]=await Promise.all([
      jwtVerify(evidence.approvalJwt,approvalKey,{
        algorithms:["RS256"],issuer:config.approvalAuthority.issuer,
        audience:config.approvalAuthority.audience,maxTokenAge:"5m"
      }),
      jwtVerify(evidence.releaseJwt,releaseKey,{
        algorithms:["RS256"],issuer:config.releaseAuthority.issuer,
        audience:config.releaseAuthority.audience,maxTokenAge:"24h"
      })
    ]);
    const now=Math.floor(Date.now()/1000);
    const claim=approval.payload;
    for(const [name,value] of [
      ["purpose","folio.manual-redrive.approval.v1"],
      ["commissionId",scope.commissionId],["reviewId",scope.reviewId],
      ["requestKey",scope.requestKey],["approvalRef",scope.approvalRef],
      ["operatorSubject",operatorSubject],["decision","approved"]
    ] as const)mustMatch(claim,name,value);
    if(claim.mfa!=="verified"
      || !recentTimestamp(claim.mfaAt,now,MAX_MFA_AGE_SECONDS)
      || !Number.isSafeInteger(claim.iat)||!Number.isSafeInteger(claim.exp)
      || claim.exp!<=now) {
      throw new OperatorAuthorizationError("Fresh signed MFA approval required");
    }
    const releaseClaim=release.payload;
    mustMatch(releaseClaim,"purpose","folio.inspector.release.v1");
    mustMatch(releaseClaim,"imageDigest",requiredDigest);
    mustMatch(releaseClaim,"cveGate","pass");
    if(!SHA.test(String(releaseClaim.sbomSha256??""))
      || !SHA.test(String(releaseClaim.auditSha256??""))
      || !recentTimestamp(releaseClaim.auditedAt,now,24*60*60)
      || typeof releaseClaim.signaturesFreshUntil!=="number"
      || !Number.isSafeInteger(releaseClaim.signaturesFreshUntil)
      || releaseClaim.signaturesFreshUntil<=now
      || releaseClaim.signaturesFreshUntil>now+72*60*60
      || !Number.isSafeInteger(releaseClaim.iat)||!Number.isSafeInteger(releaseClaim.exp)
      || releaseClaim.exp!<=now) {
      throw new OperatorAuthorizationError("Signed inspector release attestation incomplete or stale");
    }
    const expiresAt=Math.min(claim.exp!,releaseClaim.exp!,
      (claim.mfaAt as number)+MAX_MFA_AGE_SECONDS,
      releaseClaim.signaturesFreshUntil)*1000;
    if(expiresAt<=Date.now())throw new OperatorAuthorizationError("Authorization expired");
    const evidenceBytes=new TextEncoder().encode(JSON.stringify([
      evidence.approvalJwt,evidence.releaseJwt
    ]));
    const attestationDigest=[...new Uint8Array(await crypto.subtle.digest("SHA-256",evidenceBytes))]
      .map(b=>b.toString(16).padStart(2,"0")).join("");
    const proof=Object.freeze({
      operatorSubject,commissionId:scope.commissionId,reviewId:scope.reviewId,
      requestKey:scope.requestKey,approvalRef:scope.approvalRef,
      imageDigest:requiredDigest,attestationDigest,expiresAt,
      [proofBrand]:true as const
    });
    signedProofs.add(proof);
    return proof;
  }catch{
    // Distinguish neither the Access identity nor the authority that failed.
    throw new OperatorAuthorizationError("Independent signed authorization could not be verified");
  }
}
