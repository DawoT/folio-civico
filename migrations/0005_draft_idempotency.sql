-- Idempotent observation creation per authenticated author and commission.
-- Store a digest of the canonical client-controlled payload, excluding server-generated time.
ALTER TABLE observations ADD COLUMN draft_request_key TEXT;
ALTER TABLE observations ADD COLUMN draft_payload_sha256 TEXT;
CREATE UNIQUE INDEX idx_observations_author_request
  ON observations(commission_id, author_subject, draft_request_key)
  WHERE draft_request_key IS NOT NULL;
CREATE TRIGGER observations_request_fingerprint_insert
BEFORE INSERT ON observations
WHEN (NEW.draft_request_key IS NULL) <> (NEW.draft_payload_sha256 IS NULL)
  OR (NEW.draft_request_key IS NOT NULL AND
      (length(NEW.draft_request_key) < 8 OR length(NEW.draft_request_key) > 96
       OR length(NEW.draft_payload_sha256) != 64))
BEGIN SELECT RAISE(ABORT, 'INVALID_DRAFT_IDEMPOTENCY'); END;
