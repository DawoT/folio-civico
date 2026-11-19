-- 0009: trusted text processing. The original PDF remains private under quarantine/.
-- A report can only be created by trusted server-side code that verifies an
-- external inspector's HMAC signature and rehashes the original R2 bytes.
CREATE TABLE document_processing_reports (
  document_version_id TEXT PRIMARY KEY REFERENCES document_versions(id) ON DELETE RESTRICT,
  scanner_name TEXT NOT NULL CHECK (length(scanner_name) BETWEEN 3 AND 80),
  scanner_report_id TEXT NOT NULL UNIQUE CHECK (length(scanner_report_id) BETWEEN 8 AND 96),
  scanned_at TEXT NOT NULL,
  source_sha256 TEXT NOT NULL CHECK (length(source_sha256)=64),
  manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256)=64),
  page_count INTEGER NOT NULL CHECK (page_count BETWEEN 1 AND 100),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER processing_report_guards BEFORE INSERT ON document_processing_reports BEGIN
  SELECT RAISE(ABORT,'PROCESSING_REPORT_REQUIRES_QUARANTINED_VERSION')
  WHERE NOT EXISTS (
    SELECT 1 FROM document_versions v WHERE v.id=NEW.document_version_id
    AND v.sha256=NEW.source_sha256 AND v.r2_object_key LIKE 'quarantine/%'
    AND v.extraction_status IN ('pending','processing')
  );
END;
CREATE TRIGGER processing_report_no_update BEFORE UPDATE ON document_processing_reports
BEGIN SELECT RAISE(ABORT,'PROCESSING_REPORT_IMMUTABLE'); END;
CREATE TRIGGER processing_report_no_delete BEFORE DELETE ON document_processing_reports
BEGIN SELECT RAISE(ABORT,'PROCESSING_REPORT_IMMUTABLE'); END;

CREATE TRIGGER document_version_never_ready_at_insert BEFORE INSERT ON document_versions
WHEN NEW.extraction_status='ready'
BEGIN SELECT RAISE(ABORT,'READY_REQUIRES_INSPECTED_REPORT'); END;

CREATE TRIGGER document_version_ready_guard BEFORE UPDATE OF extraction_status ON document_versions
WHEN NEW.extraction_status='ready' AND OLD.extraction_status<>'ready'
BEGIN
  SELECT RAISE(ABORT,'READY_REQUIRES_INSPECTED_REPORT')
  WHERE NOT EXISTS (
    SELECT 1 FROM document_processing_reports r
    WHERE r.document_version_id=NEW.id AND r.source_sha256=NEW.sha256
      AND r.page_count=NEW.page_count
  );
  SELECT RAISE(ABORT,'READY_REQUIRES_COMPLETE_PAGES')
  WHERE NOT EXISTS (
    SELECT 1 FROM document_pages p WHERE p.document_version_id=NEW.id
    GROUP BY p.document_version_id
    HAVING COUNT(*)=NEW.page_count AND MIN(p.page)=1 AND MAX(p.page)=NEW.page_count
      AND SUM(CASE WHEN p.extraction_status='ready' THEN 0 ELSE 1 END)=0
  );
END;

CREATE TRIGGER no_new_pages_after_ready BEFORE INSERT ON document_pages
WHEN EXISTS (SELECT 1 FROM document_versions v
             WHERE v.id=NEW.document_version_id AND v.extraction_status='ready')
BEGIN SELECT RAISE(ABORT,'READY_PAGES_IMMUTABLE'); END;
CREATE TRIGGER no_modified_pages_after_ready BEFORE UPDATE ON document_pages
WHEN EXISTS (SELECT 1 FROM document_versions v
             WHERE v.id=OLD.document_version_id AND v.extraction_status='ready')
BEGIN SELECT RAISE(ABORT,'READY_PAGES_IMMUTABLE'); END;
CREATE TRIGGER no_deleted_pages_after_ready BEFORE DELETE ON document_pages
WHEN EXISTS (SELECT 1 FROM document_versions v
             WHERE v.id=OLD.document_version_id AND v.extraction_status='ready')
BEGIN SELECT RAISE(ABORT,'READY_PAGES_IMMUTABLE'); END;

-- Replace prior triggers, preserving all access rules. The trusted report,
-- not an unsafe relocation of original PDF bytes, now gates page evidence.
DROP TRIGGER observation_evidence_provenance;
CREATE TRIGGER observation_evidence_provenance
BEFORE INSERT ON observation_evidence
BEGIN
  SELECT RAISE(ABORT, 'EVIDENCE_TYPE_OR_COMMISSION_MISMATCH')
    WHERE json_extract(NEW.reference_json,'$.type') IS NOT NEW.type
      OR NOT EXISTS (
        SELECT 1 FROM observations o
        WHERE o.id = NEW.observation_id
          AND o.commission_id = json_extract(NEW.reference_json,'$.commissionId')
      );

  -- Official-source citations require a future immutable source snapshot store.
  SELECT RAISE(ABORT, 'OFFICIAL_SOURCE_NOT_VERIFIED')
    WHERE NEW.type = 'OFFICIAL_SOURCE';

  SELECT RAISE(ABORT, 'INVALID_SEARCH_SCOPE')
    WHERE NEW.type = 'SEARCH_SCOPE'
      AND NOT EXISTS (
        SELECT 1 FROM observations o
        JOIN checklist_items ci ON ci.id = json_extract(NEW.reference_json,'$.checklistItemId')
          AND ci.commission_id = o.commission_id
        JOIN document_batches b ON b.id = json_extract(NEW.reference_json,'$.batchId')
          AND b.commission_id = o.commission_id
        JOIN commission_members m ON m.commission_id = o.commission_id
          AND m.subject = json_extract(NEW.reference_json,'$.reviewerId')
          AND m.active = 1
        WHERE o.id = NEW.observation_id
          AND ci.status IN ('pending','not_located')
          AND o.author_subject = m.subject
          AND json_type(NEW.reference_json,'$.searchedAt') = 'text'
          AND strftime('%Y-%m-%dT%H:%M:%fZ',json_extract(NEW.reference_json,'$.searchedAt')) =
              json_extract(NEW.reference_json,'$.searchedAt')
      );

  SELECT RAISE(ABORT, 'UNVERIFIED_DOCUMENT_PAGE')
    WHERE NEW.type = 'DOCUMENT_PAGE'
      AND NOT EXISTS (
        SELECT 1 FROM observations o
        JOIN document_versions v ON v.id = json_extract(NEW.reference_json,'$.documentVersionId')
        JOIN documents d ON d.id = v.document_id AND d.commission_id = o.commission_id
        JOIN document_pages p ON p.document_version_id = v.id
          AND p.page = json_extract(NEW.reference_json,'$.page')
        WHERE o.id = NEW.observation_id
          AND v.sha256 = json_extract(NEW.reference_json,'$.sha256')
          AND v.extraction_status = 'ready'
          AND EXISTS (SELECT 1 FROM document_processing_reports pr WHERE pr.document_version_id=v.id AND pr.source_sha256=v.sha256)
          AND p.extraction_status = 'ready'
          AND p.page >= 1 AND v.page_count >= p.page
      );
END;

DROP TRIGGER observation_transition_guard;
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
            AND v.extraction_status='ready' AND EXISTS (SELECT 1 FROM document_processing_reports pr WHERE pr.document_version_id=v.id AND pr.source_sha256=v.sha256)
            AND p.page=json_extract(e.reference_json,'$.page')
            AND p.extraction_status='ready' AND v.page_count>=p.page
        ))
        OR e.type='OFFICIAL_SOURCE'
      )
    );
END;


