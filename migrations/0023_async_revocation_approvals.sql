-- 0023 · Independent asynchronous two-person revocation workflow.
-- No cloud bindings, keys, or active deployment routes are created.
CREATE TABLE processing_async_revocation_requests(
  id TEXT PRIMARY KEY CHECK(length(id)=36),
  actor_subject TEXT NOT NULL CHECK(length(actor_subject) BETWEEN 1 AND 200),
  request_key TEXT NOT NULL CHECK(length(request_key) BETWEEN 8 AND 96
    AND request_key NOT GLOB '*[^A-Za-z0-9_-]*'),
  kind TEXT NOT NULL CHECK(kind IN(
    'operator','approval_ref','attestation','image','approval_key','release_key'
  )),
  target TEXT NOT NULL,
  incident_ref TEXT NOT NULL CHECK(length(incident_ref) BETWEEN 12 AND 64),
  target_sha256 TEXT NOT NULL CHECK(length(target_sha256)=64),
  reason_sha256 TEXT NOT NULL CHECK(length(reason_sha256)=64),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','approved')),
  approver_subject TEXT,
  approval_sha256 TEXT,
  approval_key_thumbprint TEXT,
  requested_at INTEGER NOT NULL DEFAULT(unixepoch()),
  expires_at INTEGER NOT NULL,
  decided_at INTEGER,
  UNIQUE(actor_subject,request_key),
  CHECK(
    (status='pending' AND approver_subject IS NULL
      AND approval_sha256 IS NULL AND approval_key_thumbprint IS NULL AND decided_at IS NULL)
    OR (status='approved' AND approver_subject IS NOT NULL
      AND approver_subject<>actor_subject
      AND approval_sha256 IS NOT NULL AND approval_key_thumbprint IS NOT NULL
      AND decided_at IS NOT NULL)
  ),
  CHECK(expires_at>requested_at AND expires_at<=requested_at+86400)
);
CREATE INDEX idx_async_revocation_pending
  ON processing_async_revocation_requests(status,expires_at);
-- An abandoned pending request must never prevent a new independent urgent
-- proposal for the same revoked target; only the final denylist is unique.
CREATE INDEX idx_async_revocation_by_target
  ON processing_async_revocation_requests(kind,target,status);

CREATE TRIGGER async_revocation_request_insert_guard
BEFORE INSERT ON processing_async_revocation_requests
BEGIN
  SELECT RAISE(ABORT,'ASYNC_REVOCATION_INVALID_REQUEST')
    WHERE NEW.status<>'pending' OR NEW.approver_subject IS NOT NULL
      OR NEW.approval_sha256 IS NOT NULL OR NEW.decided_at IS NOT NULL
      OR NEW.expires_at<=unixepoch() OR NEW.expires_at>unixepoch()+86400
      OR EXISTS (
        SELECT 1 FROM processing_redrive_revocations r
        WHERE r.kind=NEW.kind AND r.target=NEW.target
      );
END;
CREATE TRIGGER async_revocation_request_no_delete
BEFORE DELETE ON processing_async_revocation_requests
BEGIN SELECT RAISE(ABORT,'ASYNC_REVOCATION_IMMUTABLE'); END;
CREATE TRIGGER async_revocation_request_update_guard
BEFORE UPDATE ON processing_async_revocation_requests
BEGIN
  SELECT RAISE(ABORT,'ASYNC_REVOCATION_IMMUTABLE') WHERE
    NEW.id IS NOT OLD.id
    OR NEW.actor_subject IS NOT OLD.actor_subject
    OR NEW.request_key IS NOT OLD.request_key
    OR NEW.kind IS NOT OLD.kind
    OR NEW.target IS NOT OLD.target
    OR NEW.incident_ref IS NOT OLD.incident_ref
    OR NEW.target_sha256 IS NOT OLD.target_sha256
    OR NEW.reason_sha256 IS NOT OLD.reason_sha256
    OR NEW.payload_sha256 IS NOT OLD.payload_sha256
    OR NEW.requested_at IS NOT OLD.requested_at;
  -- A pending request may be shortened (revocation of its pending authorization)
  -- but never extended. This is a fail-closed administrative kill switch.
  SELECT RAISE(ABORT,'ASYNC_REVOCATION_TRANSITION') WHERE NOT (
    (OLD.status='pending' AND NEW.status='pending'
      AND NEW.expires_at<OLD.expires_at
      AND NEW.approver_subject IS OLD.approver_subject
      AND NEW.approval_sha256 IS OLD.approval_sha256
      AND NEW.approval_key_thumbprint IS OLD.approval_key_thumbprint
      AND NEW.decided_at IS OLD.decided_at)
    OR
    (OLD.status='pending' AND NEW.status='approved'
      AND NEW.expires_at IS OLD.expires_at AND unixepoch()<OLD.expires_at
      AND NEW.approver_subject<>OLD.actor_subject
      AND NEW.approval_sha256 IS NOT NULL
      AND NEW.approval_key_thumbprint IS NOT NULL
      AND NEW.decided_at IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM processing_redrive_revocation_actions a
        JOIN processing_redrive_revocations r
          ON r.kind=a.kind AND r.target=a.target AND r.incident_ref=a.incident_ref
        WHERE a.kind=OLD.kind AND a.target=OLD.target
          AND a.actor_subject=OLD.actor_subject
          AND a.approver_subject=NEW.approver_subject
          AND a.request_key=OLD.request_key
          AND a.incident_ref=OLD.incident_ref
          AND a.target_sha256=OLD.target_sha256
          AND a.reason_sha256=OLD.reason_sha256
          AND a.approval_sha256=NEW.approval_sha256
          AND a.approval_key_thumbprint=NEW.approval_key_thumbprint
      )
    )
  );
END;
