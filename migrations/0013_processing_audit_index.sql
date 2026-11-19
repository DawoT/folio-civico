-- 0013: Optimize bounded, read-only PDF processing backlog audits.
-- No Queue bindings, no cron, no data changes and no automatic redrive.
CREATE INDEX IF NOT EXISTS idx_processing_outbox_audit_time
  ON document_processing_outbox(created_at, document_version_id);
