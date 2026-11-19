-- 0012: outbox state must not pretend processing completed without an
-- immutable signed inspection report. Keep 0011 migration history unchanged.
CREATE TRIGGER processing_outbox_verified_completion
BEFORE UPDATE OF state ON document_processing_outbox
WHEN NEW.state='completed' AND NOT EXISTS (
  SELECT 1 FROM document_processing_reports r
  WHERE r.document_version_id=NEW.document_version_id
)
BEGIN SELECT RAISE(ABORT,'OUTBOX_COMPLETION_REQUIRES_INSPECTION_REPORT'); END;

CREATE TRIGGER processing_outbox_no_reopen
BEFORE UPDATE OF state ON document_processing_outbox
WHEN OLD.state='completed' AND NEW.state<>'completed'
BEGIN SELECT RAISE(ABORT,'COMPLETED_PROCESSING_CANNOT_REOPEN'); END;

CREATE TRIGGER processing_outbox_id_immutable
BEFORE UPDATE OF document_version_id ON document_processing_outbox
BEGIN SELECT RAISE(ABORT,'PROCESSING_JOB_ID_IMMUTABLE'); END;

CREATE TRIGGER processing_outbox_no_delete
BEFORE DELETE ON document_processing_outbox
BEGIN SELECT RAISE(ABORT,'PROCESSING_JOB_RETENTION_REQUIRED'); END;
