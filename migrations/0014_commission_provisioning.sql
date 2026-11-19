-- 0014: idempotent, auditable president-only pilot provisioning.
-- Creating a batch/checklist item is a distinct administrative action, not a
-- modification of an existing observation or official transfer record.
CREATE TABLE commission_provisioning_requests (
  commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
  actor_subject TEXT NOT NULL,
  request_key TEXT NOT NULL CHECK (length(request_key) BETWEEN 8 AND 96),
  operation TEXT NOT NULL CHECK (operation IN ('batch','checklist')),
  payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
  resource_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (commission_id, actor_subject, request_key)
);

CREATE TRIGGER commission_provisioning_no_update
BEFORE UPDATE ON commission_provisioning_requests
BEGIN SELECT RAISE(ABORT,'PROVISIONING_REQUEST_IMMUTABLE'); END;

CREATE TRIGGER commission_provisioning_no_delete
BEFORE DELETE ON commission_provisioning_requests
BEGIN SELECT RAISE(ABORT,'PROVISIONING_REQUEST_IMMUTABLE'); END;
