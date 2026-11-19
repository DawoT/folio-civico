-- 0019 · One-shot operator redrive ledger.
-- NOT bound to the API, MCP, cron or live Worker. An approved R2.4
-- recommendation alone grants no Queue access.
CREATE TABLE processing_manual_redrives(
 id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 8 AND 64),
 commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
 recovery_review_id TEXT NOT NULL UNIQUE REFERENCES processing_recovery_reviews(id) ON DELETE RESTRICT,
 document_version_id TEXT NOT NULL UNIQUE REFERENCES document_versions(id) ON DELETE RESTRICT,
 source_sha256 TEXT NOT NULL CHECK(length(source_sha256)=64),
 operator_subject TEXT NOT NULL,
 request_key TEXT NOT NULL CHECK(length(request_key) BETWEEN 8 AND 96),
 operator_approval_ref TEXT NOT NULL CHECK(length(operator_approval_ref) BETWEEN 8 AND 64),
 request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64),
 state TEXT NOT NULL DEFAULT 'reserved'
   CHECK(state IN ('reserved','sent','uncertain','halted')),
 outcome_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(operator_subject,request_key),
 CHECK(
   (state='reserved' AND outcome_at IS NULL)
   OR (state<>'reserved' AND outcome_at IS NOT NULL)
 )
);
CREATE INDEX idx_manual_redrives_status
  ON processing_manual_redrives(state,created_at);

-- DB checks cannot attest the upstream JWT or inspector CVE gate.
-- They DO make it impossible to insert forged institution/review/outbox state
-- or bypass separation of duties merely by constructing arbitrary SQL rows.
CREATE TRIGGER processing_manual_redrive_insert_guard
BEFORE INSERT ON processing_manual_redrives
BEGIN
  SELECT RAISE(ABORT,'MANUAL_REDRIVE_NOT_ELIGIBLE') WHERE
    NEW.state<>'reserved' OR NEW.outcome_at IS NOT NULL
    OR NOT EXISTS(
      SELECT 1 FROM processing_recovery_reviews r
      JOIN commissions c ON c.id=r.commission_id
      JOIN document_versions v ON v.id=r.document_version_id
      JOIN documents d ON d.id=v.document_id
      JOIN document_processing_outbox o ON o.document_version_id=v.id
      JOIN commission_members requester ON requester.commission_id=c.id
      JOIN commission_members reviewer ON reviewer.commission_id=c.id
      WHERE r.id=NEW.recovery_review_id
        AND r.document_version_id=NEW.document_version_id
        AND r.commission_id=NEW.commission_id
        AND d.commission_id=r.commission_id
        AND r.source_sha256=NEW.source_sha256 AND v.sha256=NEW.source_sha256
        AND r.status='endorsed_for_operator_review'
        AND r.reviewed_by<>r.requested_by
        AND r.requested_by<>NEW.operator_subject AND r.reviewed_by<>NEW.operator_subject
        AND r.incident_ref<>NEW.operator_approval_ref
        AND c.status='active' AND v.extraction_status='pending'
        AND requester.subject=r.requested_by AND requester.active=1
        AND requester.role='president'
        AND reviewer.subject=r.reviewed_by AND reviewer.active=1
        AND reviewer.role IN ('president','member')
        AND o.state='sent' AND o.attempts=10 AND o.last_sent_at IS NOT NULL
        AND NOT EXISTS(
          SELECT 1 FROM document_processing_reports pr
          WHERE pr.document_version_id=v.id
        )
        AND NOT EXISTS(
          SELECT 1 FROM commission_members member
          WHERE member.commission_id=c.id AND member.subject=NEW.operator_subject
        )
    );
END;

CREATE TRIGGER processing_manual_redrive_no_delete
BEFORE DELETE ON processing_manual_redrives
BEGIN SELECT RAISE(ABORT,'MANUAL_REDRIVE_IMMUTABLE'); END;

CREATE TRIGGER processing_manual_redrive_transition_guard
BEFORE UPDATE ON processing_manual_redrives
BEGIN
  SELECT RAISE(ABORT,'MANUAL_REDRIVE_IMMUTABLE')
    WHERE NEW.id IS NOT OLD.id
      OR NEW.commission_id IS NOT OLD.commission_id
      OR NEW.recovery_review_id IS NOT OLD.recovery_review_id
      OR NEW.document_version_id IS NOT OLD.document_version_id
      OR NEW.source_sha256 IS NOT OLD.source_sha256
      OR NEW.operator_subject IS NOT OLD.operator_subject
      OR NEW.request_key IS NOT OLD.request_key
      OR NEW.operator_approval_ref IS NOT OLD.operator_approval_ref
      OR NEW.request_sha256 IS NOT OLD.request_sha256
      OR NEW.created_at IS NOT OLD.created_at;
  SELECT RAISE(ABORT,'MANUAL_REDRIVE_TRANSITION')
    WHERE OLD.state<>'reserved'
      OR NEW.state NOT IN ('sent','uncertain','halted')
      OR NEW.outcome_at IS NULL;
END;
