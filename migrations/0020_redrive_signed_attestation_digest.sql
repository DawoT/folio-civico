-- 0020: bind each redrive reservation to the exact signed approval/release
-- attestations without storing the JWTs. Legacy rows remain readable.
ALTER TABLE processing_manual_redrives
  ADD COLUMN authorization_sha256 TEXT
  CHECK(authorization_sha256 IS NULL OR
    (length(authorization_sha256)=64 AND authorization_sha256 NOT GLOB '*[^0-9a-f]*'));

CREATE TRIGGER processing_manual_redrive_authorization_required
BEFORE INSERT ON processing_manual_redrives
WHEN NEW.authorization_sha256 IS NULL
BEGIN SELECT RAISE(ABORT,'MANUAL_REDRIVE_ATTESTATION_REQUIRED'); END;

CREATE TRIGGER processing_manual_redrive_authorization_immutable
BEFORE UPDATE ON processing_manual_redrives
WHEN NEW.authorization_sha256 IS NOT OLD.authorization_sha256
BEGIN SELECT RAISE(ABORT,'MANUAL_REDRIVE_IMMUTABLE'); END;
