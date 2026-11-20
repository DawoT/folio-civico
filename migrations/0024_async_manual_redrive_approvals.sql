-- 0024 · Independent, asynchronous operator redrive approval.
-- No public routes; no remote migration or Queue binding.
CREATE TABLE processing_async_redrive_requests(
  id TEXT PRIMARY KEY CHECK(length(id)=36),
  commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
  recovery_review_id TEXT NOT NULL REFERENCES processing_recovery_reviews(id) ON DELETE RESTRICT,
  operator_subject TEXT NOT NULL CHECK(length(operator_subject) BETWEEN 1 AND 200),
  request_key TEXT NOT NULL CHECK(length(request_key) BETWEEN 8 AND 96
    AND request_key NOT GLOB '*[^A-Za-z0-9_-]*'),
  approval_ref TEXT NOT NULL CHECK(length(approval_ref) BETWEEN 12 AND 64
    AND approval_ref LIKE 'OPR_%'),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved')),
  approver_subject TEXT,
  approval_sha256 TEXT,
  approval_key_thumbprint TEXT,
  requested_at INTEGER NOT NULL DEFAULT(unixepoch()),
  expires_at INTEGER NOT NULL,
  approved_at INTEGER,
  UNIQUE(operator_subject,request_key),
  CHECK(expires_at>requested_at AND expires_at<=requested_at+86400),
  CHECK(
    (status='pending' AND approver_subject IS NULL
      AND approval_sha256 IS NULL AND approval_key_thumbprint IS NULL AND approved_at IS NULL)
    OR
    (status='approved' AND approver_subject IS NOT NULL
      AND approver_subject<>operator_subject
      AND length(approval_sha256)=64
      AND length(approval_key_thumbprint)=43
      AND approved_at IS NOT NULL)
  )
);
CREATE INDEX idx_async_redrive_status
  ON processing_async_redrive_requests(status,expires_at);

CREATE TABLE processing_async_redrive_approvals(
  request_id TEXT PRIMARY KEY
    REFERENCES processing_async_redrive_requests(id) ON DELETE RESTRICT,
  operator_subject TEXT NOT NULL,
  approver_subject TEXT NOT NULL,
  approval_sha256 TEXT NOT NULL CHECK(length(approval_sha256)=64
    AND approval_sha256 NOT GLOB '*[^0-9a-f]*'),
  approval_key_thumbprint TEXT NOT NULL CHECK(length(approval_key_thumbprint)=43),
  approved_at INTEGER NOT NULL DEFAULT(unixepoch()),
  CHECK(operator_subject<>approver_subject)
);

CREATE TRIGGER async_redrive_request_no_delete
BEFORE DELETE ON processing_async_redrive_requests
BEGIN SELECT RAISE(ABORT,'ASYNC_REDRIVE_IMMUTABLE'); END;
CREATE TRIGGER async_redrive_request_insert_guard
BEFORE INSERT ON processing_async_redrive_requests
BEGIN
  SELECT RAISE(ABORT,'ASYNC_REDRIVE_INVALID')
    WHERE NEW.status<>'pending'
      OR NEW.expires_at<=unixepoch() OR NEW.expires_at>unixepoch()+86400
      OR NOT EXISTS(
        SELECT 1 FROM processing_recovery_reviews r
        JOIN commissions c ON c.id=r.commission_id
        WHERE r.id=NEW.recovery_review_id
          AND r.commission_id=NEW.commission_id
          AND c.status='active'
          AND r.status='endorsed_for_operator_review'
          AND r.requested_by<>NEW.operator_subject
          AND r.reviewed_by<>NEW.operator_subject
          AND r.incident_ref<>NEW.approval_ref
          AND NOT EXISTS (
            SELECT 1 FROM processing_redrive_revocations revoked
            WHERE revoked.kind='operator' AND revoked.target=NEW.operator_subject
          )
          AND NOT EXISTS(
            SELECT 1 FROM commission_members m
            WHERE m.commission_id=r.commission_id
              AND m.subject=NEW.operator_subject
          )
      );
END;
CREATE TRIGGER async_redrive_request_update_guard
BEFORE UPDATE ON processing_async_redrive_requests
BEGIN
  SELECT RAISE(ABORT,'ASYNC_REDRIVE_IMMUTABLE')
    WHERE NEW.id IS NOT OLD.id OR NEW.commission_id IS NOT OLD.commission_id
      OR NEW.recovery_review_id IS NOT OLD.recovery_review_id
      OR NEW.operator_subject IS NOT OLD.operator_subject
      OR NEW.request_key IS NOT OLD.request_key
      OR NEW.approval_ref IS NOT OLD.approval_ref
      OR NEW.requested_at IS NOT OLD.requested_at;
  SELECT RAISE(ABORT,'ASYNC_REDRIVE_TRANSITION') WHERE NOT (
    (OLD.status='pending' AND NEW.status='pending'
      AND NEW.expires_at<OLD.expires_at
      AND NEW.approver_subject IS NULL AND NEW.approval_sha256 IS NULL
      AND NEW.approval_key_thumbprint IS NULL AND NEW.approved_at IS NULL)
    OR
    (OLD.status='pending' AND NEW.status='approved'
      AND NEW.expires_at IS OLD.expires_at AND OLD.expires_at>unixepoch()
      AND NEW.approver_subject<>OLD.operator_subject
      AND NEW.approval_sha256 IS NOT NULL
      AND NEW.approval_key_thumbprint IS NOT NULL AND NEW.approved_at IS NOT NULL
      AND EXISTS(
        SELECT 1 FROM processing_async_redrive_approvals a
        WHERE a.request_id=OLD.id AND a.operator_subject=OLD.operator_subject
          AND a.approver_subject=NEW.approver_subject
          AND a.approval_sha256=NEW.approval_sha256
          AND a.approval_key_thumbprint=NEW.approval_key_thumbprint
      ))
  );
END;
CREATE TRIGGER async_redrive_approval_no_update
BEFORE UPDATE ON processing_async_redrive_approvals
BEGIN SELECT RAISE(ABORT,'ASYNC_REDRIVE_APPROVAL_IMMUTABLE'); END;
CREATE TRIGGER async_redrive_approval_no_delete
BEFORE DELETE ON processing_async_redrive_approvals
BEGIN SELECT RAISE(ABORT,'ASYNC_REDRIVE_APPROVAL_IMMUTABLE'); END;
CREATE TRIGGER async_redrive_approval_insert_guard
BEFORE INSERT ON processing_async_redrive_approvals
BEGIN
  SELECT RAISE(ABORT,'ASYNC_REDRIVE_APPROVAL_INVALID') WHERE NOT EXISTS(
    SELECT 1 FROM processing_async_redrive_requests p
    WHERE p.id=NEW.request_id AND p.status='pending'
      AND p.expires_at>unixepoch() AND p.operator_subject=NEW.operator_subject
      AND p.operator_subject<>NEW.approver_subject
      AND NOT EXISTS (
        SELECT 1 FROM processing_redrive_revocations revoked
        WHERE revoked.kind='operator' AND revoked.target=NEW.approver_subject
      )
  );
END;

ALTER TABLE processing_manual_redrives ADD COLUMN async_request_id TEXT
  REFERENCES processing_async_redrive_requests(id) ON DELETE RESTRICT;
ALTER TABLE processing_manual_redrives ADD COLUMN async_approval_sha256 TEXT
  CHECK(async_approval_sha256 IS NULL OR
    (length(async_approval_sha256)=64
      AND async_approval_sha256 NOT GLOB '*[^0-9a-f]*'));
CREATE UNIQUE INDEX idx_manual_redrive_async_request
  ON processing_manual_redrives(async_request_id)
  WHERE async_request_id IS NOT NULL;
CREATE TRIGGER processing_manual_redrive_async_guard
BEFORE INSERT ON processing_manual_redrives
BEGIN
  SELECT RAISE(ABORT,'ASYNC_REDRIVE_APPROVAL_REQUIRED') WHERE
    (NEW.async_request_id IS NULL)<>(NEW.async_approval_sha256 IS NULL);
  SELECT RAISE(ABORT,'ASYNC_REDRIVE_NOT_APPROVED') WHERE
    NEW.async_request_id IS NOT NULL AND NOT EXISTS(
      SELECT 1 FROM processing_async_redrive_requests p
      JOIN processing_async_redrive_approvals a ON a.request_id=p.id
      WHERE p.id=NEW.async_request_id AND p.status='approved'
        AND p.expires_at>unixepoch()
        AND p.operator_subject=NEW.operator_subject
        AND p.commission_id=NEW.commission_id
        AND p.recovery_review_id=NEW.recovery_review_id
        AND p.request_key=NEW.request_key
        AND p.approval_ref=NEW.operator_approval_ref
        AND a.approval_sha256=NEW.async_approval_sha256
        AND p.approval_sha256=NEW.async_approval_sha256
        AND p.approver_subject=a.approver_subject
        AND p.approval_key_thumbprint=a.approval_key_thumbprint
        AND NOT EXISTS (
          SELECT 1 FROM processing_redrive_revocations revoked
          WHERE revoked.kind='operator' AND revoked.target=p.approver_subject
        )
    );
END;
CREATE TRIGGER processing_manual_redrive_async_immutable
BEFORE UPDATE ON processing_manual_redrives
WHEN NEW.async_request_id IS NOT OLD.async_request_id
  OR NEW.async_approval_sha256 IS NOT OLD.async_approval_sha256
BEGIN SELECT RAISE(ABORT,'MANUAL_REDRIVE_IMMUTABLE'); END;
