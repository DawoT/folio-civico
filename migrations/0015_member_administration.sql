-- Commission membership lifecycle: stable revisions and immutable request journal.
-- Existing active members retain revision=1 after migration.
ALTER TABLE commission_members ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision BETWEEN 1 AND 2147483647);

CREATE TABLE commission_member_actions (
  commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
  actor_subject TEXT NOT NULL,
  request_key TEXT NOT NULL CHECK (length(request_key) BETWEEN 8 AND 96),
  member_subject TEXT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('grant','revoke')),
  payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256)=64),
  result_role TEXT NOT NULL CHECK (result_role IN ('president','member','advisor','observer')),
  result_active INTEGER NOT NULL CHECK (result_active IN (0,1)),
  result_revision INTEGER NOT NULL CHECK (result_revision > 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (commission_id,actor_subject,request_key)
);

CREATE TRIGGER commission_member_actions_immutable_update
BEFORE UPDATE ON commission_member_actions
BEGIN SELECT RAISE(ABORT,'MEMBERSHIP_ACTION_IMMUTABLE'); END;
CREATE TRIGGER commission_member_actions_immutable_delete
BEFORE DELETE ON commission_member_actions
BEGIN SELECT RAISE(ABORT,'MEMBERSHIP_ACTION_IMMUTABLE'); END;

CREATE INDEX commission_members_active_role ON commission_members(commission_id,active,role);
