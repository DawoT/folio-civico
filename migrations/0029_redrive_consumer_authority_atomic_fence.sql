-- R2.12b/P6 · atomic D1 fence for revocations and proposal expiry.
-- Only local/synthetic verification. No institutional authority, deployment
-- permissions, or runtime bindings are granted by this schema.
--
-- P5's triggers block institutional invalidations. These independent
-- guards close the consumer preflight -> D1 write gap for R2.7 authority
-- withdrawal, an expired/invalid async approval and a halted reservation.
-- A VIEW centralizes the predicate for both report and 422 status writes.
CREATE VIEW processing_redrive_consumer_denials AS
SELECT m.document_version_id AS document_version_id
FROM processing_manual_redrives m
LEFT JOIN processing_async_redrive_requests a
  ON a.id=m.async_request_id
LEFT JOIN processing_institutional_approval_evidence e
  ON e.purpose='redrive' AND e.request_id=m.async_request_id
WHERE m.state NOT IN ('reserved','sent','uncertain')
  OR (
    m.async_request_id IS NOT NULL
    AND (
      a.status IS NOT 'approved'
      OR a.approval_sha256 IS NOT m.async_approval_sha256
      OR a.expires_at IS NULL OR a.expires_at<=unixepoch()
      OR (a.institutional_gate_required=1 AND e.case_revision IS NULL)
    )
  )
  OR EXISTS (
    SELECT 1 FROM processing_redrive_revocations r
    WHERE (r.kind='operator' AND r.target=m.operator_subject)
       OR (r.kind='operator' AND r.target=a.approver_subject)
       OR (r.kind='approval_ref' AND r.target=m.operator_approval_ref)
       OR (r.kind='attestation' AND r.target=m.authorization_sha256)
       OR (r.kind='image' AND r.target=m.image_digest)
       OR (r.kind='approval_key' AND r.target=m.approval_key_thumbprint)
       OR (r.kind='release_key' AND r.target=m.release_key_thumbprint)
  );

CREATE TRIGGER processing_redrive_consumer_report_authority_guard
BEFORE INSERT ON document_processing_reports
WHEN EXISTS (
  SELECT 1 FROM processing_redrive_consumer_denials
  WHERE document_version_id=NEW.document_version_id
)
BEGIN SELECT RAISE(ABORT,'REDRIVE_CONSUMER_AUTHORITY_DENIED'); END;

-- A 422 unsafe-verdict decision would also persist a state change. Make
-- that write fail inside D1 if revocation/expiry races the last preflight.
CREATE TRIGGER processing_redrive_consumer_status_authority_guard
BEFORE UPDATE OF extraction_status ON document_versions
WHEN NEW.extraction_status<>OLD.extraction_status
  AND NEW.extraction_status IN ('ready','needs_review')
  AND EXISTS (
    SELECT 1 FROM processing_redrive_consumer_denials
    WHERE document_version_id=OLD.id
  )
BEGIN SELECT RAISE(ABORT,'REDRIVE_CONSUMER_AUTHORITY_DENIED'); END;
