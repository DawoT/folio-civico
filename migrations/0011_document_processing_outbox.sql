-- 0011: Every uploaded version creates an atomic, durable outbox record.
-- Enqueueing to Cloudflare Queues is a separate, at-least-once operation.
CREATE TABLE document_processing_outbox (
 document_version_id TEXT PRIMARY KEY REFERENCES document_versions(id) ON DELETE RESTRICT,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','sent','completed')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
 last_sent_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_processing_outbox_pending
 ON document_processing_outbox(state,attempts,created_at);

CREATE TRIGGER document_processing_outbox_insert
AFTER INSERT ON document_versions WHEN NEW.extraction_status='pending'
BEGIN
 INSERT INTO document_processing_outbox(document_version_id) VALUES(NEW.id);
END;

-- Migration backfill for uploads preceding the outbox feature. Never enqueue
-- previously admitted, revoked or failed processing records.
INSERT OR IGNORE INTO document_processing_outbox(document_version_id)
 SELECT v.id FROM document_versions v WHERE v.extraction_status='pending';

CREATE TRIGGER document_processing_outbox_completed
AFTER INSERT ON document_processing_reports
BEGIN
 UPDATE document_processing_outbox SET state='completed'
 WHERE document_version_id=NEW.document_version_id;
END;
