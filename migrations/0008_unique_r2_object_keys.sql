-- Ensure each private R2 object key belongs to exactly one document version.
-- Reconciliation assumes a one-to-one version/object relationship.
CREATE UNIQUE INDEX idx_document_versions_r2_object_key
  ON document_versions(r2_object_key);
