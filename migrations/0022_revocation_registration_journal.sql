-- 0022 · Private, transaction-bound revocation registration journal.
-- No runtime endpoint. Only code holding a verified, sealed incident approval
-- can use the isolated writer; D1 privileges remain a separate trust boundary.
CREATE TABLE processing_redrive_revocation_actions (
  actor_subject TEXT NOT NULL CHECK(length(actor_subject) BETWEEN 1 AND 200),
  request_key TEXT NOT NULL
    CHECK(length(request_key) BETWEEN 8 AND 96 AND
      request_key NOT GLOB '*[^A-Za-z0-9_-]*'),
  kind TEXT NOT NULL CHECK(kind IN (
    'operator','approval_ref','attestation','image','approval_key','release_key'
  )),
  target TEXT NOT NULL,
  incident_ref TEXT NOT NULL
    CHECK(length(incident_ref) BETWEEN 12 AND 64 AND
      incident_ref NOT GLOB '*[^A-Za-z0-9_-]*'),
  approver_subject TEXT NOT NULL CHECK(length(approver_subject) BETWEEN 1 AND 200),
  target_sha256 TEXT NOT NULL CHECK(length(target_sha256)=64
    AND target_sha256 NOT GLOB '*[^0-9a-f]*'),
  reason_sha256 TEXT NOT NULL CHECK(length(reason_sha256)=64
    AND reason_sha256 NOT GLOB '*[^0-9a-f]*'),
  approval_sha256 TEXT NOT NULL CHECK(length(approval_sha256)=64
    AND approval_sha256 NOT GLOB '*[^0-9a-f]*'),
  approval_key_thumbprint TEXT NOT NULL CHECK(length(approval_key_thumbprint)=43
    AND approval_key_thumbprint NOT GLOB '*[^A-Za-z0-9_-]*'),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64
    AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(actor_subject,request_key),
  UNIQUE(kind,target),
  CHECK(actor_subject<>approver_subject)
);
CREATE INDEX idx_redrive_revocation_actions_incident
  ON processing_redrive_revocation_actions(incident_ref,created_at);

CREATE TRIGGER processing_redrive_revocation_actions_no_update
BEFORE UPDATE ON processing_redrive_revocation_actions
BEGIN SELECT RAISE(ABORT,'REVOCATION_ACTION_IMMUTABLE'); END;
CREATE TRIGGER processing_redrive_revocation_actions_no_delete
BEFORE DELETE ON processing_redrive_revocation_actions
BEGIN SELECT RAISE(ABORT,'REVOCATION_ACTION_IMMUTABLE'); END;

-- Reject standalone inserts into the original denylist. The journal row
-- and the matching denylist entry must be in the SAME atomic D1 batch.
-- A direct D1 administrator with write access can still forge both rows:
-- SQL alone cannot verify JWTs, so remote D1 access MUST remain restricted.
CREATE TRIGGER processing_redrive_revocations_requires_journal
BEFORE INSERT ON processing_redrive_revocations
WHEN NOT EXISTS (
  SELECT 1 FROM processing_redrive_revocation_actions a
  WHERE a.kind=NEW.kind AND a.target=NEW.target
    AND a.incident_ref=NEW.incident_ref
)
BEGIN SELECT RAISE(ABORT,'REVOCATION_AUTHORIZATION_REQUIRED'); END;
