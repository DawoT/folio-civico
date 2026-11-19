-- Independent trusted-operator bootstrap journal. No public or anonymous path.
CREATE TABLE commission_bootstrap_requests (
  operator_subject TEXT NOT NULL,
  request_key TEXT NOT NULL CHECK (length(request_key) BETWEEN 8 AND 96),
  commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  initial_president_subject TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256)=64),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (operator_subject,request_key)
);

CREATE TRIGGER commission_bootstrap_immutable_update
BEFORE UPDATE ON commission_bootstrap_requests
BEGIN SELECT RAISE(ABORT,'BOOTSTRAP_IMMUTABLE'); END;
CREATE TRIGGER commission_bootstrap_immutable_delete
BEFORE DELETE ON commission_bootstrap_requests
BEGIN SELECT RAISE(ABORT,'BOOTSTRAP_IMMUTABLE'); END;
