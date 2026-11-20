-- 0021 · Append-only, fail-closed manual redrive revocation ledger.
-- Private D1 only: no route, key rotation automation, or privileged writer.
CREATE TABLE processing_redrive_revocations(
  kind TEXT NOT NULL CHECK(kind IN (
    'operator','approval_ref','attestation','image','approval_key','release_key'
  )),
  target TEXT NOT NULL,
  incident_ref TEXT NOT NULL
    CHECK(length(incident_ref) BETWEEN 8 AND 64 AND
      incident_ref NOT GLOB '*[^A-Za-z0-9_-]*'),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(kind,target),
  CHECK(
    (kind='operator' AND length(target) BETWEEN 1 AND 200)
    OR (kind='approval_ref' AND length(target) BETWEEN 12 AND 64
      AND target LIKE 'OPR_%')
    OR (kind='attestation' AND length(target)=64
      AND target NOT GLOB '*[^0-9a-f]*')
    OR (kind='image' AND length(target)=71
      AND substr(target,1,7)='sha256:'
      AND substr(target,8) NOT GLOB '*[^0-9a-f]*')
    OR (kind IN ('approval_key','release_key') AND length(target)=43
      AND target NOT GLOB '*[^A-Za-z0-9_-]*')
  )
);

CREATE TRIGGER processing_redrive_revocations_no_update
BEFORE UPDATE ON processing_redrive_revocations
BEGIN SELECT RAISE(ABORT,'REDRIVE_REVOCATION_IMMUTABLE'); END;
CREATE TRIGGER processing_redrive_revocations_no_delete
BEFORE DELETE ON processing_redrive_revocations
BEGIN SELECT RAISE(ABORT,'REDRIVE_REVOCATION_IMMUTABLE'); END;

-- Existing ledger rows are retained; new reservations must disclose the
-- inspected image digest and both signing-key thumbprints to the DB guard.
ALTER TABLE processing_manual_redrives ADD COLUMN image_digest TEXT
  CHECK(image_digest IS NULL OR (length(image_digest)=71 AND
    substr(image_digest,1,7)='sha256:' AND
    substr(image_digest,8) NOT GLOB '*[^0-9a-f]*'));
ALTER TABLE processing_manual_redrives ADD COLUMN approval_key_thumbprint TEXT
  CHECK(approval_key_thumbprint IS NULL OR length(approval_key_thumbprint)=43);
ALTER TABLE processing_manual_redrives ADD COLUMN release_key_thumbprint TEXT
  CHECK(release_key_thumbprint IS NULL OR length(release_key_thumbprint)=43);

CREATE TRIGGER processing_manual_redrive_revocation_insert_guard
BEFORE INSERT ON processing_manual_redrives
BEGIN
  SELECT RAISE(ABORT,'MANUAL_REDRIVE_PROVENANCE_REQUIRED')
    WHERE NEW.image_digest IS NULL
      OR NEW.approval_key_thumbprint IS NULL
      OR NEW.release_key_thumbprint IS NULL;
  SELECT RAISE(ABORT,'MANUAL_REDRIVE_REVOKED') WHERE EXISTS (
    SELECT 1 FROM processing_redrive_revocations r
    WHERE (r.kind='operator' AND r.target=NEW.operator_subject)
       OR (r.kind='approval_ref' AND r.target=NEW.operator_approval_ref)
       OR (r.kind='attestation' AND r.target=NEW.authorization_sha256)
       OR (r.kind='image' AND r.target=NEW.image_digest)
       OR (r.kind='approval_key' AND r.target=NEW.approval_key_thumbprint)
       OR (r.kind='release_key' AND r.target=NEW.release_key_thumbprint)
  );
END;

CREATE TRIGGER processing_manual_redrive_revocation_fields_immutable
BEFORE UPDATE ON processing_manual_redrives
WHEN NEW.image_digest IS NOT OLD.image_digest
  OR NEW.approval_key_thumbprint IS NOT OLD.approval_key_thumbprint
  OR NEW.release_key_thumbprint IS NOT OLD.release_key_thumbprint
BEGIN SELECT RAISE(ABORT,'MANUAL_REDRIVE_IMMUTABLE'); END;
