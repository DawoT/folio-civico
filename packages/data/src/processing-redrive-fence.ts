/**
 * Consumer-side authorization fence for a manually redriven PDF. The opaque
 * Queue tag is only a lookup key, never independent authorization. D1 remains
 * the authority for the one-shot claim, signed approval and revocations.
 *
 * A source without any manual reservation remains the ordinary outbox path.
 * Once a manual reservation exists, a tag is MANDATORY: stripping it must
 * never downgrade to ordinary dispatch. D1 read failures MUST propagate.
 */
interface RedriveRow {
  id:string;
  state:"reserved"|"sent"|"uncertain"|"halted";
  sourceSha256:string;
  asyncRequestId:string|null;
  asyncApprovalDigest:string|null;
  proposalStatus:"pending"|"approved"|null;
  proposalDigest:string|null;
  proposalExpiresAt:number|null;
  institutionalGateRequired:number|null;
  evidenceRevision:number|null;
  revoked:number;
  invalidated:number;
}
export async function isProcessingRedriveAuthorized(
  db:D1Database,versionId:string,sourceSha256:string,
  manualRedriveId?:string
):Promise<boolean>{
  const row=await db.prepare(`
    SELECT
      m.id,m.state,m.source_sha256 AS sourceSha256,
      m.async_request_id AS asyncRequestId,
      m.async_approval_sha256 AS asyncApprovalDigest,
      a.status AS proposalStatus,a.approval_sha256 AS proposalDigest,
      a.expires_at AS proposalExpiresAt,
      a.institutional_gate_required AS institutionalGateRequired,
      e.case_revision AS evidenceRevision,
      CASE WHEN EXISTS(
        SELECT 1 FROM processing_institutional_approval_invalidations i
        WHERE i.purpose='redrive' AND i.request_id=m.async_request_id
      ) THEN 1 ELSE 0 END AS invalidated,
      CASE WHEN EXISTS(
        SELECT 1 FROM processing_redrive_revocations revoked
        WHERE (revoked.kind='operator' AND revoked.target=m.operator_subject)
          OR (revoked.kind='operator' AND revoked.target=a.approver_subject)
          OR (revoked.kind='approval_ref' AND revoked.target=m.operator_approval_ref)
          OR (revoked.kind='attestation' AND revoked.target=m.authorization_sha256)
          OR (revoked.kind='image' AND revoked.target=m.image_digest)
          OR (revoked.kind='approval_key' AND revoked.target=m.approval_key_thumbprint)
          OR (revoked.kind='release_key' AND revoked.target=m.release_key_thumbprint)
      ) THEN 1 ELSE 0 END AS revoked
    FROM processing_manual_redrives m
    LEFT JOIN processing_async_redrive_requests a ON a.id=m.async_request_id
    LEFT JOIN processing_institutional_approval_evidence e
      ON e.purpose='redrive' AND e.request_id=m.async_request_id
    WHERE m.document_version_id=?
  `).bind(versionId).first<RedriveRow>();
  if(!row)return manualRedriveId===undefined;
  if(manualRedriveId===undefined || row.id!==manualRedriveId
    || row.sourceSha256!==sourceSha256
    || !["reserved","sent","uncertain"].includes(row.state)
    || row.revoked!==0 || row.invalidated!==0)return false;
  if(row.asyncRequestId!==null){
    if(row.proposalStatus!=="approved"
      || row.asyncApprovalDigest!==row.proposalDigest
      || row.proposalExpiresAt===null
      || row.proposalExpiresAt<=Math.floor(Date.now()/1000)
      || (row.institutionalGateRequired===1 && row.evidenceRevision===null)){
      return false;
    }
  }
  return true;
}
