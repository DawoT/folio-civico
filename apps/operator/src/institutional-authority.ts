/**
 * R2.12b preparatory boundary: read current evidence FROM a trusted institutional
 * system. No implementation of that external source is shipped. A signed JWS or
 * client-provided case reference alone is never an institutional decision.
 * The synthetic-only host may opt in to this gate for contract tests.
 */
export type InstitutionalPurpose="revocation"|"redrive";
export interface InstitutionalEvidenceQuery {
  purpose:InstitutionalPurpose;
  caseRef:string;
  requestId:string;
  actorSubject:string;
  approverSubject:string;
  scopeDigest:string;
  approvalDigest:string;
  /** Bound signed approval/proposal deadline in epoch milliseconds. */
  expiresAt:number;
}
export interface InstitutionalEvidenceSnapshot extends InstitutionalEvidenceQuery {
  revision:number;
  status:"open"|"closed"|"cancelled";
  decision:"approved"|"rejected";
  reviewerSubject:string;
  /** All dates below are epoch seconds, from the independent institution. */
  checkedAt:number;
  reviewedAt:number;
  mfaVerifiedAt:number;
  validUntil:number;
}
export interface InstitutionalEvidenceReader {
  /** Query must be executed server-to-server, not reconstructed from request JSON. */
  readCurrentEvidence(expected:Readonly<InstitutionalEvidenceQuery>):Promise<unknown>;
}
export class InstitutionalEvidenceDenied extends Error {}
export class InstitutionalEvidenceUnavailable extends Error {}

const DIGEST=/^[0-9a-f]{64}$/;
const MAX_CHECK_AGE=15;
const MAX_MFA_AGE=300;
const MAX_CLOCK_SKEW=5;
function validTime(value:unknown):value is number {
  return typeof value==="number" && Number.isSafeInteger(value) && value>0;
}

/**
 * This asserts the returned record is CURRENT, approved, reviewable and exactly
 * bound to the signed decision. No caller may pass an untrusted port selected
 * from HTTP request content. This cannot attest the reader's real authority.
 */
export async function checkCurrentInstitutionalEvidence(
  reader:InstitutionalEvidenceReader|undefined,
  expected:Readonly<InstitutionalEvidenceQuery>
):Promise<Readonly<{revision:number;checkedAt:number}>> {
  if(!reader || typeof reader.readCurrentEvidence!=="function")
    throw new InstitutionalEvidenceUnavailable("Independent incident reader is not configured");
  const nowMs=Date.now(),now=Math.floor(nowMs/1000);
  if(!expected || !validTime(expected.expiresAt) || expected.expiresAt<=nowMs
    || !DIGEST.test(expected.scopeDigest) || !DIGEST.test(expected.approvalDigest)
    || !["revocation","redrive"].includes(expected.purpose)
    || !expected.caseRef || !expected.requestId || !expected.actorSubject
    || !expected.approverSubject || expected.actorSubject===expected.approverSubject)
    throw new InstitutionalEvidenceDenied("Invalid institutional evidence scope");
  let record:unknown;
  try{
    record=await reader.readCurrentEvidence(Object.freeze({...expected}));
  }catch{
    // Never expose the provider response, URLs, secrets or case details.
    throw new InstitutionalEvidenceUnavailable("Independent incident source unavailable");
  }
  if(!record || typeof record!=="object" || Array.isArray(record))
    throw new InstitutionalEvidenceDenied("Independent incident evidence not found");
  const snap=record as Partial<InstitutionalEvidenceSnapshot>;
  for(const key of [
    "purpose","caseRef","requestId","actorSubject","approverSubject",
    "scopeDigest","approvalDigest","expiresAt"
  ] as const){
    if(snap[key]!==expected[key])
      throw new InstitutionalEvidenceDenied("Institutional evidence scope mismatch");
  }
  if(snap.status!=="open" || snap.decision!=="approved"
    || snap.reviewerSubject!==expected.approverSubject
    || !validTime(snap.revision) || !validTime(snap.checkedAt)
    || !validTime(snap.reviewedAt) || !validTime(snap.mfaVerifiedAt)
    || !validTime(snap.validUntil)
    || snap.checkedAt<now-MAX_CHECK_AGE || snap.checkedAt>now+MAX_CLOCK_SKEW
    || snap.reviewedAt>snap.checkedAt || snap.reviewedAt<now-MAX_MFA_AGE
    || snap.mfaVerifiedAt>snap.reviewedAt || snap.mfaVerifiedAt<now-MAX_MFA_AGE
    || snap.validUntil<=now){
    throw new InstitutionalEvidenceDenied("Institutional approval is not current");
  }
  return Object.freeze({revision:snap.revision,checkedAt:snap.checkedAt});
}
