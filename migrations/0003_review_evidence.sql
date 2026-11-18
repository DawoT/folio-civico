-- 0003: evidence provenance enforced at the database boundary.
-- These triggers guard against cross-commission citations even if an API precheck races.
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
          AND v.r2_object_key NOT LIKE 'quarantine/%'
          AND p.extraction_status = 'ready'
          AND p.page >= 1 AND v.page_count >= p.page
      );
END;

-- Evidence records are append-only; edits must create a new proposal/revision.
CREATE TRIGGER observation_evidence_no_update BEFORE UPDATE ON observation_evidence
BEGIN SELECT RAISE(ABORT, 'EVIDENCE_IMMUTABLE'); END;
CREATE TRIGGER observation_evidence_no_delete BEFORE DELETE ON observation_evidence
BEGIN SELECT RAISE(ABORT, 'EVIDENCE_IMMUTABLE'); END;

CREATE INDEX idx_observation_evidence_observation ON observation_evidence(observation_id, created_at);
