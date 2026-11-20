-- R2.12b/P2: local-only institutional evidence receipts for synthetic workflows.
-- Do not infer that these records certify a real IdP, human decision or provider.
-- The marker is set when the synthetic adapter is configured with an external
-- reader; SQL prevents dropping that requirement after the proposal is stored.
ALTER TABLE processing_async_revocation_requests
  ADD COLUMN institutional_gate_required INTEGER NOT NULL DEFAULT 0
  CHECK(institutional_gate_required IN (0,1));
ALTER TABLE processing_async_redrive_requests
  ADD COLUMN institutional_gate_required INTEGER NOT NULL DEFAULT 0
  CHECK(institutional_gate_required IN (0,1));

CREATE TABLE processing_institutional_approval_evidence (
  purpose TEXT NOT NULL CHECK(purpose IN ('revocation','redrive')),
  request_id TEXT NOT NULL CHECK(length(request_id)=36),
  actor_subject TEXT NOT NULL CHECK(length(actor_subject) BETWEEN 1 AND 200),
  approver_subject TEXT NOT NULL CHECK(length(approver_subject) BETWEEN 1 AND 200),
  scope_sha256 TEXT NOT NULL CHECK(length(scope_sha256)=64
    AND scope_sha256 NOT GLOB '*[^0-9a-f]*'),
  approval_sha256 TEXT NOT NULL CHECK(length(approval_sha256)=64
    AND approval_sha256 NOT GLOB '*[^0-9a-f]*'),
  case_revision INTEGER NOT NULL CHECK(case_revision>0),
  checked_at INTEGER NOT NULL CHECK(checked_at>0),
  expires_at INTEGER NOT NULL CHECK(expires_at>0),
  recorded_at INTEGER NOT NULL DEFAULT(unixepoch()),
  PRIMARY KEY(purpose,request_id),
  CHECK(actor_subject<>approver_subject)
);

CREATE TRIGGER institutional_evidence_no_update
BEFORE UPDATE ON processing_institutional_approval_evidence
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_EVIDENCE_IMMUTABLE'); END;
CREATE TRIGGER institutional_evidence_no_delete
BEFORE DELETE ON processing_institutional_approval_evidence
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_EVIDENCE_IMMUTABLE'); END;

-- Check the D1 proposal and record the receipt in the SAME transaction as
-- the human approval. No JWT, JWS, reason or case contents are stored.
CREATE TRIGGER institutional_evidence_insert_guard
BEFORE INSERT ON processing_institutional_approval_evidence
WHEN NEW.checked_at<unixepoch()-15 OR NEW.checked_at>unixepoch()+5
  OR NEW.expires_at<=unixepoch()
  OR NOT (
    (NEW.purpose='revocation' AND EXISTS (
      SELECT 1 FROM processing_async_revocation_requests p
      WHERE p.id=NEW.request_id AND p.status='pending'
        AND p.expires_at=NEW.expires_at
        AND p.actor_subject=NEW.actor_subject
        AND p.actor_subject<>NEW.approver_subject
    ))
    OR
    (NEW.purpose='redrive' AND EXISTS (
      SELECT 1 FROM processing_async_redrive_requests p
      WHERE p.id=NEW.request_id AND p.status='pending'
        AND p.expires_at=NEW.expires_at
        AND p.operator_subject=NEW.actor_subject
        AND p.operator_subject<>NEW.approver_subject
    ))
  )
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_EVIDENCE_INVALID'); END;

CREATE TRIGGER async_revocation_institutional_gate_immutable
BEFORE UPDATE ON processing_async_revocation_requests
WHEN NEW.institutional_gate_required<>OLD.institutional_gate_required
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_GATE_IMMUTABLE'); END;

CREATE TRIGGER async_redrive_institutional_gate_immutable
BEFORE UPDATE ON processing_async_redrive_requests
WHEN NEW.institutional_gate_required<>OLD.institutional_gate_required
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_GATE_IMMUTABLE'); END;

-- Fail closed against both an omitted external read and a forged SQL
-- transition of a proposal explicitly marked as institutionally gated.
CREATE TRIGGER async_revocation_institutional_transition
BEFORE UPDATE OF status ON processing_async_revocation_requests
WHEN OLD.status='pending' AND NEW.status='approved'
  AND OLD.institutional_gate_required=1
  AND NOT EXISTS (
    SELECT 1 FROM processing_institutional_approval_evidence e
    WHERE e.purpose='revocation' AND e.request_id=OLD.id
      AND e.actor_subject=OLD.actor_subject
      AND e.approver_subject=NEW.approver_subject
      AND e.approval_sha256=NEW.approval_sha256
      AND e.expires_at=OLD.expires_at
      AND e.checked_at>=unixepoch()-15
      AND e.checked_at<=unixepoch()+5
  )
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_EVIDENCE_REQUIRED'); END;

CREATE TRIGGER async_redrive_institutional_transition
BEFORE UPDATE OF status ON processing_async_redrive_requests
WHEN OLD.status='pending' AND NEW.status='approved'
  AND OLD.institutional_gate_required=1
  AND NOT EXISTS (
    SELECT 1 FROM processing_institutional_approval_evidence e
    WHERE e.purpose='redrive' AND e.request_id=OLD.id
      AND e.actor_subject=OLD.operator_subject
      AND e.approver_subject=NEW.approver_subject
      AND e.approval_sha256=NEW.approval_sha256
      AND e.expires_at=OLD.expires_at
      AND e.checked_at>=unixepoch()-15
      AND e.checked_at<=unixepoch()+5
  )
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_EVIDENCE_REQUIRED'); END;
