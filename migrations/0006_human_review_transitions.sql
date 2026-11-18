-- Review workflow: two-person decision with immutable evidence and DB-level gates.
ALTER TABLE observations ADD COLUMN submitted_by TEXT;
ALTER TABLE observations ADD COLUMN submitted_at TEXT;
ALTER TABLE observations ADD COLUMN submit_request_key TEXT;
ALTER TABLE observations ADD COLUMN reviewed_by TEXT;
ALTER TABLE observations ADD COLUMN reviewed_at TEXT;
ALTER TABLE observations ADD COLUMN review_note TEXT;
ALTER TABLE observations ADD COLUMN review_request_key TEXT;

CREATE TRIGGER observation_transition_guard
BEFORE UPDATE OF status ON observations
WHEN NEW.status <> OLD.status
BEGIN
  SELECT RAISE(ABORT, 'INVALID_OBSERVATION_TRANSITION')
    WHERE NOT (
      (OLD.status='draft' AND NEW.status='in_review')
      OR (OLD.status='in_review' AND NEW.status IN ('validated','dismissed'))
    );

  SELECT RAISE(ABORT, 'REVIEW_REQUIRES_ACTIVE_COMMISSION')
    WHERE NOT EXISTS (
      SELECT 1 FROM commissions c WHERE c.id=OLD.commission_id AND c.status='active'
    );

  SELECT RAISE(ABORT, 'REVIEW_REQUIRES_EVIDENCE')
    WHERE NOT EXISTS (SELECT 1 FROM observation_evidence e WHERE e.observation_id=OLD.id);

  SELECT RAISE(ABORT, 'INVALID_SUBMISSION_IDENTITY')
    WHERE NEW.status='in_review' AND (
      NEW.submitted_by IS NULL OR NEW.submitted_by <> OLD.author_subject
      OR NEW.submitted_at IS NULL OR NEW.submit_request_key IS NULL
      OR length(NEW.submit_request_key) < 8 OR length(NEW.submit_request_key) > 96
      OR NOT EXISTS (
        SELECT 1 FROM commission_members m WHERE m.commission_id=OLD.commission_id
          AND m.subject=NEW.submitted_by AND m.active=1
          AND m.role IN ('president','member','advisor')
      )
    );

  SELECT RAISE(ABORT, 'INVALID_REVIEWER_IDENTITY')
    WHERE NEW.status IN ('validated','dismissed') AND (
      NEW.reviewed_by IS NULL OR NEW.reviewed_by=OLD.author_subject
      OR NEW.reviewed_at IS NULL OR NEW.review_request_key IS NULL
      OR length(NEW.review_request_key) < 8 OR length(NEW.review_request_key) > 96
      OR NEW.review_note IS NULL OR length(trim(NEW.review_note)) < 15
      OR length(NEW.review_note) > 1000
      OR NOT EXISTS (
        SELECT 1 FROM commission_members m WHERE m.commission_id=OLD.commission_id
          AND m.subject=NEW.reviewed_by AND m.active=1 AND m.role IN ('president','member')
      )
    );

  SELECT RAISE(ABORT, 'INVALID_VALIDATION_SIGNATURE')
    WHERE NEW.status='validated'
      AND (NEW.validated_by IS NULL OR NEW.validated_by<>NEW.reviewed_by
           OR NEW.validated_at IS NULL);

  SELECT RAISE(ABORT, 'REVIEW_EVIDENCE_STALE')
    WHERE NEW.status='validated' AND EXISTS (
      SELECT 1 FROM observation_evidence e
      WHERE e.observation_id=OLD.id AND (
        (e.type='SEARCH_SCOPE' AND NOT EXISTS (
          SELECT 1 FROM checklist_items ci
          JOIN document_batches b ON b.id=json_extract(e.reference_json,'$.batchId')
            AND b.commission_id=ci.commission_id
          WHERE ci.id=json_extract(e.reference_json,'$.checklistItemId')
            AND ci.commission_id=OLD.commission_id
            AND ci.status IN ('pending','not_located')
        ))
        OR (e.type='DOCUMENT_PAGE' AND NOT EXISTS (
          SELECT 1 FROM document_versions v
          JOIN documents d ON d.id=v.document_id AND d.commission_id=OLD.commission_id
          JOIN document_pages p ON p.document_version_id=v.id
          WHERE v.id=json_extract(e.reference_json,'$.documentVersionId')
            AND v.sha256=json_extract(e.reference_json,'$.sha256')
            AND v.extraction_status='ready' AND v.r2_object_key NOT LIKE 'quarantine/%'
            AND p.page=json_extract(e.reference_json,'$.page')
            AND p.extraction_status='ready' AND v.page_count>=p.page
        ))
        OR e.type='OFFICIAL_SOURCE'
      )
    );
END;

CREATE TRIGGER observation_transition_audit
AFTER UPDATE OF status ON observations
WHEN NEW.status <> OLD.status
BEGIN
  INSERT INTO audit_events(id,commission_id,actor_subject,action,resource_type,resource_id,metadata_json)
  VALUES(lower(hex(randomblob(16))),NEW.commission_id,
    CASE WHEN NEW.status='in_review' THEN NEW.submitted_by ELSE NEW.reviewed_by END,
    'observation.' || CASE NEW.status WHEN 'in_review' THEN 'submitted' ELSE NEW.status END,
    'observation', NEW.id,
    json_object('from',OLD.status,'to',NEW.status,
      'reviewNote',CASE WHEN NEW.status='in_review' THEN NULL ELSE NEW.review_note END));
END;

CREATE TRIGGER observation_core_immutable
BEFORE UPDATE OF title, description, author_subject, commission_id ON observations
BEGIN SELECT RAISE(ABORT,'OBSERVATION_CORE_IMMUTABLE'); END;
