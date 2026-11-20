-- R2.12b/P7: closed commissions must not admit scanner results.
-- An independent D1 trigger protects against closure after the last
-- preflight but before the one-shot 422 or clean-report transaction.
-- There are no new endpoints or remote resources.
CREATE TRIGGER processing_report_active_commission_guard
BEFORE INSERT ON document_processing_reports
WHEN NOT EXISTS (
  SELECT 1 FROM document_versions v
  JOIN documents d ON d.id=v.document_id
  JOIN commissions c ON c.id=d.commission_id
  WHERE v.id=NEW.document_version_id AND c.status='active'
)
BEGIN SELECT RAISE(ABORT,'PROCESSING_COMMISSION_CLOSED'); END;

CREATE TRIGGER processing_status_active_commission_guard
BEFORE UPDATE OF extraction_status ON document_versions
WHEN NEW.extraction_status IN ('ready','needs_review')
  AND NOT EXISTS (
    SELECT 1 FROM documents d
    JOIN commissions c ON c.id=d.commission_id
    WHERE d.id=OLD.document_id AND c.status='active'
  )
BEGIN SELECT RAISE(ABORT,'PROCESSING_COMMISSION_CLOSED'); END;
