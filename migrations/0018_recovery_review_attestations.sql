-- 0018: two-person RECOVERY REVIEW ONLY. No Queue/Outbox redrive privileges.
-- A positive decision is a recommendation for an independently authorized
-- infrastructure operator; never permission to enqueue or mark a PDF ready.
CREATE TABLE processing_recovery_reviews (
 id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 8 AND 64),
 commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
 document_version_id TEXT NOT NULL UNIQUE REFERENCES document_versions(id) ON DELETE RESTRICT,
 source_sha256 TEXT NOT NULL CHECK(length(source_sha256)=64),
 incident_ref TEXT NOT NULL CHECK(length(incident_ref) BETWEEN 8 AND 64),
 requested_by TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'in_review'
   CHECK(status IN ('in_review','endorsed_for_operator_review','dismissed')),
 reviewed_by TEXT,
 reviewed_at TEXT,
 decision_digest TEXT CHECK(decision_digest IS NULL OR length(decision_digest)=64),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(
   (status='in_review' AND reviewed_by IS NULL AND reviewed_at IS NULL AND decision_digest IS NULL)
   OR
   (status IN ('endorsed_for_operator_review','dismissed')
      AND reviewed_by IS NOT NULL AND reviewed_by<>requested_by
      AND reviewed_at IS NOT NULL AND decision_digest IS NOT NULL)
 )
);
CREATE INDEX idx_recovery_reviews_commission ON processing_recovery_reviews(commission_id,status,created_at);

CREATE TRIGGER processing_recovery_review_insert_guard
BEFORE INSERT ON processing_recovery_reviews
BEGIN
  SELECT RAISE(ABORT,'RECOVERY_REVIEW_NOT_ELIGIBLE') WHERE
    NEW.status<>'in_review' OR NOT EXISTS (
      SELECT 1 FROM document_versions v
      JOIN documents d ON d.id=v.document_id
      JOIN commissions c ON c.id=d.commission_id
      JOIN commission_members m ON m.commission_id=c.id
      JOIN document_processing_outbox o ON o.document_version_id=v.id
      WHERE v.id=NEW.document_version_id AND d.commission_id=NEW.commission_id
        AND v.sha256=NEW.source_sha256 AND v.extraction_status='pending'
        AND c.status='active'
        AND m.subject=NEW.requested_by AND m.active=1 AND m.role='president'
        AND o.state='sent' AND o.attempts=10 AND o.last_sent_at IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM document_processing_reports r
          WHERE r.document_version_id=v.id)
    );
END;

CREATE TRIGGER processing_recovery_review_no_delete
BEFORE DELETE ON processing_recovery_reviews
BEGIN SELECT RAISE(ABORT,'RECOVERY_REVIEW_IMMUTABLE'); END;

CREATE TRIGGER processing_recovery_review_transition_guard
BEFORE UPDATE ON processing_recovery_reviews
BEGIN
  SELECT RAISE(ABORT,'RECOVERY_REVIEW_IMMUTABLE')
    WHERE NEW.id IS NOT OLD.id OR NEW.commission_id IS NOT OLD.commission_id
      OR NEW.document_version_id IS NOT OLD.document_version_id
      OR NEW.source_sha256 IS NOT OLD.source_sha256
      OR NEW.incident_ref IS NOT OLD.incident_ref
      OR NEW.requested_by IS NOT OLD.requested_by
      OR NEW.created_at IS NOT OLD.created_at;
  SELECT RAISE(ABORT,'RECOVERY_REVIEW_TRANSITION')
    WHERE OLD.status<>'in_review'
      OR NEW.status NOT IN ('endorsed_for_operator_review','dismissed')
      OR NEW.reviewed_by IS NULL OR NEW.reviewed_by=OLD.requested_by
      OR NEW.reviewed_at IS NULL OR NEW.decision_digest IS NULL;
  SELECT RAISE(ABORT,'RECOVERY_REVIEW_UNAUTHORIZED') WHERE NOT EXISTS (
    SELECT 1 FROM commissions c
    JOIN commission_members m ON m.commission_id=c.id
    WHERE c.id=OLD.commission_id AND c.status='active'
      AND m.subject=NEW.reviewed_by AND m.active=1
      AND m.role IN ('president','member')
  );
  SELECT RAISE(ABORT,'RECOVERY_REVIEW_STALE')
    WHERE NEW.status='endorsed_for_operator_review' AND NOT EXISTS (
      SELECT 1 FROM commission_members sponsor
      WHERE sponsor.commission_id=OLD.commission_id
        AND sponsor.subject=OLD.requested_by
        AND sponsor.active=1 AND sponsor.role='president'
    );
  SELECT RAISE(ABORT,'RECOVERY_REVIEW_STALE')
    WHERE NEW.status='endorsed_for_operator_review' AND NOT EXISTS (
      SELECT 1 FROM document_versions v
      JOIN documents d ON d.id=v.document_id
      JOIN document_processing_outbox o ON o.document_version_id=v.id
      WHERE v.id=OLD.document_version_id AND d.commission_id=OLD.commission_id
        AND v.sha256=OLD.source_sha256 AND v.extraction_status='pending'
        AND o.state='sent' AND o.attempts=10 AND o.last_sent_at IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM document_processing_reports r
          WHERE r.document_version_id=v.id)
    );
END;

CREATE TABLE processing_recovery_actions (
 commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
 actor_subject TEXT NOT NULL,
 request_key TEXT NOT NULL CHECK(length(request_key) BETWEEN 8 AND 96),
 review_id TEXT NOT NULL REFERENCES processing_recovery_reviews(id) ON DELETE RESTRICT,
 action TEXT NOT NULL CHECK(action IN ('open','endorse','dismiss')),
 payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
 result_status TEXT NOT NULL CHECK(result_status IN
   ('in_review','endorsed_for_operator_review','dismissed')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(commission_id,actor_subject,request_key)
);
CREATE INDEX idx_recovery_actions_case ON processing_recovery_actions(review_id,created_at);
CREATE TRIGGER processing_recovery_actions_insert_guard
BEFORE INSERT ON processing_recovery_actions
BEGIN
  SELECT RAISE(ABORT,'RECOVERY_ACTION_SCOPE_MISMATCH') WHERE NOT EXISTS (
    SELECT 1 FROM processing_recovery_reviews r
    WHERE r.id=NEW.review_id AND r.commission_id=NEW.commission_id
      AND r.status=NEW.result_status
      AND (
        (NEW.action='open' AND r.status='in_review'
          AND r.requested_by=NEW.actor_subject)
        OR
        (NEW.action='endorse'
          AND r.status='endorsed_for_operator_review'
          AND r.reviewed_by=NEW.actor_subject)
        OR
        (NEW.action='dismiss' AND r.status='dismissed'
          AND r.reviewed_by=NEW.actor_subject)
      )
  );
END;
CREATE TRIGGER processing_recovery_actions_no_update
BEFORE UPDATE ON processing_recovery_actions
BEGIN SELECT RAISE(ABORT,'RECOVERY_ACTION_IMMUTABLE'); END;
CREATE TRIGGER processing_recovery_actions_no_delete
BEFORE DELETE ON processing_recovery_actions
BEGIN SELECT RAISE(ABORT,'RECOVERY_ACTION_IMMUTABLE'); END;
