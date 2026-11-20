/**
 * Durable, strictly scoped metadata from a fresh independent institutional
 * read. This is NOT a human-attested cryptographic proof or an IdP connector.
 * The SQL ledger binds the value atomically to a particular signed approval.
 */
export interface InstitutionalEvidenceReceipt {
  readonly caseRevision:number;
  readonly checkedAt:number;
  readonly scopeDigest:string;
}
export interface StoredInstitutionalEvidence extends InstitutionalEvidenceReceipt {
  readonly purpose:"revocation"|"redrive";
  readonly requestId:string;
  readonly actorSubject:string;
  readonly approverSubject:string;
  readonly approvalDigest:string;
  readonly expiresAt:number;
}
/**
 * Read the append-only, synthetic-only invalidation ledger.
 * A failed D1 read must reject the operation, not assume no invalidation.
 * The external institutional event writer is NOT implemented.
 */
export async function isInstitutionalApprovalInvalidated(
  db:D1Database,purpose:"revocation"|"redrive",requestId:string
):Promise<boolean>{
  const hit=await db.prepare(`
    SELECT 1 AS blocked
    FROM processing_institutional_approval_invalidations
    WHERE purpose=? AND request_id=?
    LIMIT 1
  `).bind(purpose,requestId).first<{blocked:number}>();
  return hit!==null;
}

/** A replay must reference the original immutable case revision and JWS. */
export async function matchesInstitutionalEvidence(
  db:D1Database,purpose:"revocation"|"redrive",requestId:string,
  actorSubject:string,approverSubject:string,approvalDigest:string,
  expiresAt:number,evidence:InstitutionalEvidenceReceipt
):Promise<boolean>{
  const row=await findInstitutionalEvidence(db,purpose,requestId);
  return !!row && row.actorSubject===actorSubject
    && row.approverSubject===approverSubject
    && row.approvalDigest===approvalDigest
    && row.expiresAt===expiresAt
    && row.scopeDigest===evidence.scopeDigest
    && row.caseRevision===evidence.caseRevision;
}
export async function findInstitutionalEvidence(
  db:D1Database,purpose:"revocation"|"redrive",requestId:string
):Promise<StoredInstitutionalEvidence|null>{
  return db.prepare(`
    SELECT purpose,request_id AS requestId,actor_subject AS actorSubject,
      approver_subject AS approverSubject,scope_sha256 AS scopeDigest,
      approval_sha256 AS approvalDigest,case_revision AS caseRevision,
      checked_at AS checkedAt,expires_at AS expiresAt
    FROM processing_institutional_approval_evidence
    WHERE purpose=? AND request_id=?
  `).bind(purpose,requestId).first<StoredInstitutionalEvidence>();
}
