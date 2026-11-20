-- R2.12b/P3: an append-only D1 kill switch for institutionally-gated
-- synthetic approvals. No event source, remote writer or public endpoint.
-- A future institutional provider must authenticate/audit event delivery.
CREATE TABLE processing_institutional_approval_invalidations(
  purpose TEXT NOT NULL CHECK(purpose IN ('revocation','redrive')),
  request_id TEXT NOT NULL CHECK(length(request_id)=36),
  case_revision INTEGER NOT NULL CHECK(case_revision>0),
  reason TEXT NOT NULL CHECK(reason IN(
    'case_closed','case_superseded','reviewer_withdrawn','authority_withdrawn'
  )),
  evidence_sha256 TEXT NOT NULL CHECK(
    length(evidence_sha256)=64
    AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  invalidated_at INTEGER NOT NULL DEFAULT(unixepoch()),
  PRIMARY KEY(purpose,request_id)
);

CREATE TRIGGER institutional_invalidation_no_update
BEFORE UPDATE ON processing_institutional_approval_invalidations
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_INVALIDATION_IMMUTABLE'); END;

CREATE TRIGGER institutional_invalidation_no_delete
BEFORE DELETE ON processing_institutional_approval_invalidations
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_INVALIDATION_IMMUTABLE'); END;

CREATE TRIGGER institutional_invalidation_insert_guard
BEFORE INSERT ON processing_institutional_approval_invalidations
WHEN NOT (
  (NEW.purpose='revocation' AND EXISTS (
    SELECT 1 FROM processing_async_revocation_requests p
    WHERE p.id=NEW.request_id AND p.institutional_gate_required=1
      AND (p.status='pending' OR EXISTS (
        SELECT 1 FROM processing_institutional_approval_evidence e
        WHERE e.purpose='revocation' AND e.request_id=p.id
          AND NEW.case_revision>=e.case_revision
      ))
  ))
  OR (NEW.purpose='redrive' AND EXISTS (
    SELECT 1 FROM processing_async_redrive_requests p
    WHERE p.id=NEW.request_id AND p.institutional_gate_required=1
      AND (p.status='pending' OR EXISTS (
        SELECT 1 FROM processing_institutional_approval_evidence e
        WHERE e.purpose='redrive' AND e.request_id=p.id
          AND NEW.case_revision>=e.case_revision
      ))
  ))
)
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_INVALIDATION_INVALID'); END;

-- Resolve races between an invalidation insert and D1 decisions. These
-- triggers run in the same SQLite transaction as the proposed approval.
CREATE TRIGGER institutional_revocation_decision_invalidation_guard
BEFORE UPDATE OF status ON processing_async_revocation_requests
WHEN OLD.status='pending' AND NEW.status='approved'
  AND EXISTS (
    SELECT 1 FROM processing_institutional_approval_invalidations i
    WHERE i.purpose='revocation' AND i.request_id=OLD.id
  )
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_APPROVAL_INVALIDATED'); END;

CREATE TRIGGER institutional_redrive_decision_invalidation_guard
BEFORE UPDATE OF status ON processing_async_redrive_requests
WHEN OLD.status='pending' AND NEW.status='approved'
  AND EXISTS (
    SELECT 1 FROM processing_institutional_approval_invalidations i
    WHERE i.purpose='redrive' AND i.request_id=OLD.id
  )
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_APPROVAL_INVALIDATED'); END;

-- Protect the one-shot reservation itself if invalidation races with
-- preflight. The legacy, ungated synthetic path is unchanged.
CREATE TRIGGER institutional_redrive_reservation_invalidation_guard
BEFORE INSERT ON processing_manual_redrives
WHEN NEW.async_request_id IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM processing_institutional_approval_invalidations i
    WHERE i.purpose='redrive' AND i.request_id=NEW.async_request_id
  )
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_APPROVAL_INVALIDATED'); END;
