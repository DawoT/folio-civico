-- Folio Cívico MVP. No sensitive content is stored in logs or public object keys.
PRAGMA foreign_keys = ON;

CREATE TABLE commissions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'closed')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE commission_members (
  commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
  subject TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('president', 'member', 'advisor', 'observer')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (commission_id, subject)
);

CREATE TABLE document_batches (
  id TEXT PRIMARY KEY,
  commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
  label TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (id, commission_id)
);

CREATE TABLE documents (
  id TEXT PRIMARY KEY,
  commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
  batch_id TEXT NOT NULL,
  filename TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (batch_id, commission_id) REFERENCES document_batches(id, commission_id) ON DELETE RESTRICT
);

CREATE TABLE document_versions (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE RESTRICT,
  version_number INTEGER NOT NULL CHECK (version_number > 0),
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  r2_object_key TEXT NOT NULL,
  page_count INTEGER CHECK (page_count > 0),
  extraction_status TEXT NOT NULL DEFAULT 'pending' CHECK (
    extraction_status IN ('pending', 'processing', 'ready', 'needs_review', 'failed')
  ),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (document_id, version_number)
);

CREATE TABLE document_pages (
  document_version_id TEXT NOT NULL REFERENCES document_versions(id) ON DELETE RESTRICT,
  page INTEGER NOT NULL CHECK (page > 0),
  extracted_text TEXT,
  extraction_status TEXT NOT NULL CHECK (extraction_status IN ('ready', 'needs_review', 'failed')),
  PRIMARY KEY (document_version_id, page)
);

CREATE TABLE checklist_items (
  id TEXT PRIMARY KEY,
  commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
  area TEXT NOT NULL CHECK (area IN ('works', 'procurement')),
  expected_document TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'located', 'not_located', 'observed')),
  reviewed_by TEXT,
  reviewed_at TEXT
);

CREATE TABLE observations (
  id TEXT PRIMARY KEY,
  commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
  author_subject TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'in_review', 'validated', 'dismissed')),
  validated_by TEXT,
  validated_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK ((status = 'validated' AND validated_by IS NOT NULL AND validated_at IS NOT NULL)
      OR status <> 'validated')
);

CREATE TABLE observation_evidence (
  id TEXT PRIMARY KEY,
  observation_id TEXT NOT NULL REFERENCES observations(id) ON DELETE RESTRICT,
  type TEXT NOT NULL CHECK (type IN ('DOCUMENT_PAGE', 'SEARCH_SCOPE', 'OFFICIAL_SOURCE')),
  reference_json TEXT NOT NULL CHECK (json_valid(reference_json)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY,
  commission_id TEXT NOT NULL REFERENCES commissions(id) ON DELETE RESTRICT,
  actor_subject TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  metadata_json TEXT CHECK (metadata_json IS NULL OR json_valid(metadata_json)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_documents_commission ON documents(commission_id, batch_id);
CREATE INDEX idx_checklist_commission ON checklist_items(commission_id, area, status);
CREATE INDEX idx_observations_commission ON observations(commission_id, status, created_at);
CREATE INDEX idx_audit_commission_time ON audit_events(commission_id, created_at);
CREATE VIRTUAL TABLE document_pages_fts USING fts5(extracted_text, content='document_pages', content_rowid='rowid');
CREATE TRIGGER document_pages_ai AFTER INSERT ON document_pages BEGIN
  INSERT INTO document_pages_fts(rowid, extracted_text) VALUES (new.rowid, new.extracted_text);
END;
CREATE TRIGGER document_pages_ad AFTER DELETE ON document_pages BEGIN
  INSERT INTO document_pages_fts(document_pages_fts, rowid, extracted_text)
  VALUES ('delete', old.rowid, old.extracted_text);
END;
CREATE TRIGGER document_pages_au AFTER UPDATE ON document_pages BEGIN
  INSERT INTO document_pages_fts(document_pages_fts, rowid, extracted_text)
  VALUES ('delete', old.rowid, old.extracted_text);
  INSERT INTO document_pages_fts(rowid, extracted_text) VALUES (new.rowid, new.extracted_text);
END;
