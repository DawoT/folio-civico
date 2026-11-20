import { describe, expect, it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { getBatchAccess, getExistingUpload, listBatchDocuments, persistDocumentUpload } from "./documents";

function fixture() {
  const f = makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name) VALUES ('c_a','A'),('c_b','B');
    INSERT INTO commission_members(commission_id,subject,role,active)
      VALUES ('c_a','alice','member',1),('c_a','observer','observer',1),
             ('c_a','revoked','president',0),('c_b','bob','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES ('b_a','c_a','Lote A'),('b_b','c_b','Lote B');
  `);
  return f;
}
const upload = {
  commissionId: "c_a", batchId: "b_a", subject: "alice", documentId: "doc_1",
  versionId: "ver_1", sha256: "a".repeat(64), r2Key: "quarantine/random.pdf",
  filename: "Contrato.pdf", idempotencyKey: "upload_req_123"
};

describe("D1 document intake security and idempotency", () => {
  it("requires active membership in matching commission and batch", async () => {
    const f = fixture();
    try {
      expect(await getBatchAccess(f.db,"alice","c_a","b_a")).toMatchObject({role:"member"});
      expect(await getBatchAccess(f.db,"alice","c_b","b_b")).toBeNull();
      expect(await getBatchAccess(f.db,"revoked","c_a","b_a")).toBeNull();
      expect(await getBatchAccess(f.db,"alice","c_a","b_b")).toBeNull();
    } finally { f.close(); }
  });

  it("persists a version and an audit event atomically", async () => {
    const f = fixture();
    try {
      await persistDocumentUpload(f.db, upload);
      expect(await getExistingUpload(f.db,"alice","c_a",upload.idempotencyKey)).toMatchObject({
        documentId: "doc_1", versionId:"ver_1", sha256: upload.sha256
      });
      const rows = await listBatchDocuments(f.db,"alice","c_a","b_a");
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ id: "doc_1", extractionStatus:"pending" });
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get()).toMatchObject({n:1});
    } finally { f.close(); }
  });

  it("returns extraction status only within an active member's authorized commission", async () => {
    const f=fixture();
    try {
      await persistDocumentUpload(f.db,upload);
      f.sqlite.exec("UPDATE document_versions SET extraction_status='needs_review' WHERE id='ver_1'");
      expect(await getExistingUpload(f.db,"alice","c_a",upload.idempotencyKey)).toMatchObject({
        documentId:"doc_1",versionId:"ver_1",processingStatus:"needs_review"
      });
      expect(await getExistingUpload(f.db,"bob","c_a",upload.idempotencyKey)).toBeNull();
      expect(await getExistingUpload(f.db,"revoked","c_a",upload.idempotencyKey)).toBeNull();
      expect(await getExistingUpload(f.db,"alice","c_b",upload.idempotencyKey)).toBeNull();
    }finally{f.close();}
  });

  it("refuses a write from an observer and never creates a document", async () => {
    const f = fixture();
    try {
      await expect(persistDocumentUpload(f.db, {...upload,subject:"observer"})).rejects.toThrow();
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM documents").get()).toMatchObject({ n:0 });
    } finally { f.close(); }
  });

  it("refuses uploads after the commission is closed", async () => {
    const f=fixture();
    try {
      f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
      await expect(persistDocumentUpload(f.db,upload)).rejects.toThrow();
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM documents").get()).toMatchObject({n:0});
    } finally {f.close();}
  });

  it("refuses a wrong-commission batch even with a legitimate membership", async () => {
    const f = fixture();
    try {
      await expect(persistDocumentUpload(f.db, {...upload,batchId:"b_b"})).rejects.toThrow();
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM documents").get()).toMatchObject({ n:0 });
    } finally { f.close(); }
  });

  it("rejects duplicate idempotency keys within the same commission", async () => {
    const f = fixture();
    try {
      await persistDocumentUpload(f.db,upload);
      await expect(persistDocumentUpload(f.db,{...upload,documentId:"doc_2",versionId:"ver_2",r2Key:"quarantine/new.pdf"})).rejects.toThrow();
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM documents").get()).toMatchObject({ n:1 });
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get()).toMatchObject({ n:1 });
    } finally { f.close(); }
  });

  it("rejects one R2 object key attached to two different document versions", async () => {
    const f = fixture();
    try {
      await persistDocumentUpload(f.db,upload);
      await expect(persistDocumentUpload(f.db,{
        ...upload,documentId:"doc_2",versionId:"ver_2",idempotencyKey:"upload_req_456"
      })).rejects.toThrow();
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM document_versions").get()).toMatchObject({n:1});
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get()).toMatchObject({n:1});
    } finally {f.close();}
  });

  it("does not expose an inaccessible batch on listing", async () => {
    const f = fixture();
    try {
      await persistDocumentUpload(f.db, upload);
      expect(await listBatchDocuments(f.db, "bob","c_a","b_a")).toEqual([]);
      expect(await getExistingUpload(f.db,"bob","c_a",upload.idempotencyKey)).toBeNull();
    } finally { f.close(); }
  });
});
