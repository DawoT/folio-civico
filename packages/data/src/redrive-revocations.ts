import type {VerifiedRedriveAuthorization} from "@folio/auth";

/**
 * Read the private, append-only D1 denylist. No endpoint or write path is
 * exposed; provisioning revocations requires an independently authorized
 * incident procedure. Fail closed if this query cannot complete.
 */
export async function isManualRedriveRevoked(
  db:D1Database,proof:VerifiedRedriveAuthorization
):Promise<boolean> {
  const result=await db.prepare(`
    SELECT 1 AS blocked FROM processing_redrive_revocations r
    WHERE (r.kind='operator' AND r.target=?)
       OR (r.kind='approval_ref' AND r.target=?)
       OR (r.kind='attestation' AND r.target=?)
       OR (r.kind='image' AND r.target=?)
       OR (r.kind='approval_key' AND r.target=?)
       OR (r.kind='release_key' AND r.target=?)
    LIMIT 1
  `).bind(
    proof.operatorSubject,proof.approvalRef,proof.attestationDigest,
    proof.imageDigest,proof.approvalKeyThumbprint,proof.releaseKeyThumbprint
  ).first<{blocked:number}>();
  return result!==null;
}
