-- 0010: processed reference immutability and revocation semantics.
-- Keep 0009 unchanged: migrations already applied to local test databases.
CREATE TRIGGER document_inspected_version_immutable
BEFORE UPDATE OF sha256,r2_object_key,document_id,version_number ON document_versions
WHEN EXISTS (
  SELECT 1 FROM document_processing_reports r WHERE r.document_version_id=OLD.id
)
BEGIN SELECT RAISE(ABORT,'INSPECTED_VERSION_IMMUTABLE'); END;


CREATE TRIGGER document_inspected_page_count_immutable
BEFORE UPDATE OF page_count ON document_versions
WHEN OLD.page_count IS NOT NULL
  AND EXISTS (SELECT 1 FROM document_processing_reports r WHERE r.document_version_id=OLD.id)
BEGIN SELECT RAISE(ABORT,'INSPECTED_PAGE_COUNT_IMMUTABLE'); END;

CREATE TRIGGER document_inspected_page_no_update
BEFORE UPDATE ON document_pages
WHEN EXISTS (
  SELECT 1 FROM document_processing_reports r
  WHERE r.document_version_id=OLD.document_version_id
)
BEGIN SELECT RAISE(ABORT,'INSPECTED_PAGE_IMMUTABLE'); END;

CREATE TRIGGER document_inspected_page_no_delete
BEFORE DELETE ON document_pages
WHEN EXISTS (
  SELECT 1 FROM document_processing_reports r
  WHERE r.document_version_id=OLD.document_version_id
)
BEGIN SELECT RAISE(ABORT,'INSPECTED_PAGE_IMMUTABLE'); END;

CREATE TRIGGER document_inspected_page_no_insert
BEFORE INSERT ON document_pages
WHEN EXISTS (
  SELECT 1 FROM document_processing_reports r
  JOIN document_versions v ON v.id=r.document_version_id
  WHERE r.document_version_id=NEW.document_version_id AND v.extraction_status='ready'
)
BEGIN SELECT RAISE(ABORT,'INSPECTED_PAGE_IMMUTABLE'); END;

CREATE TRIGGER document_ready_no_reset
BEFORE UPDATE OF extraction_status ON document_versions
WHEN OLD.extraction_status='ready' AND NEW.extraction_status IN ('pending','processing')
BEGIN SELECT RAISE(ABORT,'INSPECTED_VERSION_CANNOT_REENTER_QUARANTINE'); END;
