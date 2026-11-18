-- Idempotency keys are commission-scoped; preserve the initial migration.
ALTER TABLE documents ADD COLUMN upload_request_key TEXT;
CREATE UNIQUE INDEX idx_documents_commission_upload_key
  ON documents(commission_id, upload_request_key)
  WHERE upload_request_key IS NOT NULL;
