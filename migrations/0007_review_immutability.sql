-- Harden observation integrity even against accidental direct D1 SQL writes.
-- Workflow metadata may only be populated as part of an actual status transition.
CREATE TRIGGER observation_initial_draft_only
BEFORE INSERT ON observations
WHEN NEW.status <> 'draft' OR NEW.validated_by IS NOT NULL OR NEW.validated_at IS NOT NULL
BEGIN SELECT RAISE(ABORT,'OBSERVATION_MUST_START_AS_DRAFT'); END;

CREATE TRIGGER observation_metadata_locked
BEFORE UPDATE OF submitted_by, submitted_at, submit_request_key,
  reviewed_by, reviewed_at, review_note, review_request_key,
  validated_by, validated_at, draft_request_key, draft_payload_sha256 ON observations
WHEN NEW.status = OLD.status
BEGIN SELECT RAISE(ABORT,'REVIEW_METADATA_IMMUTABLE'); END;

CREATE TRIGGER observation_no_evidence_after_submission
BEFORE INSERT ON observation_evidence
WHEN EXISTS (
  SELECT 1 FROM observations o
  WHERE o.id=NEW.observation_id AND o.status <> 'draft'
)
BEGIN SELECT RAISE(ABORT,'EVIDENCE_LOCKED_AFTER_SUBMISSION'); END;

-- The submitted transition cannot modify final reviewer metadata and vice versa.
CREATE TRIGGER observation_transition_metadata_shape
BEFORE UPDATE OF status ON observations
WHEN NEW.status <> OLD.status
BEGIN
  SELECT RAISE(ABORT,'INVALID_SUBMISSION_METADATA')
    WHERE NEW.status='in_review' AND (
      NEW.reviewed_by IS NOT NULL OR NEW.review_note IS NOT NULL OR
      NEW.reviewed_at IS NOT NULL OR NEW.review_request_key IS NOT NULL OR
      NEW.validated_by IS NOT NULL OR NEW.validated_at IS NOT NULL
    );
  SELECT RAISE(ABORT,'SUBMISSION_METADATA_CANNOT_CHANGE')
    WHERE NEW.status IN ('validated','dismissed') AND (
      NEW.submitted_by IS NOT OLD.submitted_by OR
      NEW.submitted_at IS NOT OLD.submitted_at OR
      NEW.submit_request_key IS NOT OLD.submit_request_key
    );
END;
