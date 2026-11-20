-- R2.12b/P5 · fail-closed consumer-side institutional kill switch.
-- Local migration only. No real institutional issuer, Queue or D1 binding
-- is activated by this schema. The consumer checks verified opaque redrive IDs
-- and these triggers close the remaining preflight -> D1 write race.
CREATE TRIGGER institutional_redrive_inspection_report_guard
BEFORE INSERT ON document_processing_reports
WHEN EXISTS(
  SELECT 1 FROM processing_manual_redrives m
  JOIN processing_institutional_approval_invalidations i
    ON i.purpose='redrive' AND i.request_id=m.async_request_id
  WHERE m.document_version_id=NEW.document_version_id
)
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_REDRIVE_INVALIDATED'); END;

-- Scanner's 422 unsafe status is a persistent side-effect too. Prevent it
-- after invalidation; the queue consumer will ack the cancelled message.
CREATE TRIGGER institutional_redrive_extraction_status_guard
BEFORE UPDATE OF extraction_status ON document_versions
WHEN NEW.extraction_status<>OLD.extraction_status
  AND NEW.extraction_status IN ('ready','needs_review')
  AND EXISTS(
    SELECT 1 FROM processing_manual_redrives m
    JOIN processing_institutional_approval_invalidations i
      ON i.purpose='redrive' AND i.request_id=m.async_request_id
    WHERE m.document_version_id=OLD.id
  )
BEGIN SELECT RAISE(ABORT,'INSTITUTIONAL_REDRIVE_INVALIDATED'); END;
