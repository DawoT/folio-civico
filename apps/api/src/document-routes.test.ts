import { describe, expect, it, vi } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleDocumentRequest } from "./document-routes";

const bytes = new TextEncoder().encode("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
const url = "https://api.test/api/commissions/c_a/batches/b_a/documents";

function fixture() {
  const f = makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name) VALUES ('c_a','Comision A'),('c_b','Comision B');
    INSERT INTO commission_members(commission_id,subject,role,active)
      VALUES ('c_a','alice','member',1),('c_a','viewer','observer',1),('c_b','bob','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES ('b_a','c_a','Lote A'),('b_b','c_b','Lote B');
  `);
  const objects = new Map<string,Uint8Array>();
  const put = vi.fn(async (key:string, data:Uint8Array) => {
    objects.set(key,data);
    return { key };
  });
  const del = vi.fn(async (key:string) => { objects.delete(key); });
  const bucket = { put, delete:del };
  return {...f, objects, put, del, env: { DB:f.db, DOCUMENTS:bucket as unknown as R2Bucket }};
}
function post(key = "upload_req_123", data: Uint8Array = bytes, extras: Record<string,string> = {}) {
  return new Request(url, { method:"POST", headers:{
    "Content-Type":"application/pdf", "X-Document-Filename":"Contrato.pdf", "Idempotency-Key":key, ...extras
  }, body: data as BodyInit });
}

describe("authenticated PDF intake route", () => {
  it("uploads to quarantine and writes a D1 record for the same commission", async () => {
    const f=fixture();
    try {
      const response=await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
      expect(response.status).toBe(201);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      const doc=await response.json() as { documentId:string; ingestStatus:string; sha256:string };
      expect(doc.ingestStatus).toBe("quarantined");
      expect(doc.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(f.objects.size).toBe(1);
      const list=await handleDocumentRequest(new Request(url), f.env,"alice","c_a","b_a");
      expect(list.status).toBe(200);
      expect((await list.json() as unknown[])).toHaveLength(1);
    } finally {f.close();}
  });

  it("does not store or register a valid-looking but too-short PDF header",async()=>{
    const f=fixture();
    try{
      const short=new TextEncoder().encode("%PDF-1.7");
      const response=await handleDocumentRequest(
        post("short_pdf_001",short),f.env,"alice","c_a","b_a"
      );
      expect(response.status).toBe(422);
      expect(f.put).not.toHaveBeenCalled();
      expect(f.objects.size).toBe(0);
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM documents").get())
        .toMatchObject({n:0});
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM document_processing_outbox").get())
        .toMatchObject({n:0});
    }finally{f.close();}
  });

  it("returns the original document on a retried idempotency key", async () => {
    const f=fixture();
    try {
      const first=await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
      const second=await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
      expect(second.status).toBe(200);
      expect((await second.json() as {documentId:string}).documentId).toBe(
        (await first.json() as {documentId:string}).documentId
      );
      expect(f.put).toHaveBeenCalledTimes(1);
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM documents").get()).toMatchObject({n:1});
    } finally {f.close();}
  });

  it("preserves the original upload while reporting intermediate and failed processing states",async()=>{
    const f=fixture();
    try{
      const created=await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
      const first=await created.json() as {documentId:string;versionId:string;sha256:string;processingStatus:string};
      expect(first.processingStatus).toBe("pending");
      for(const processingStatus of ["processing","failed"] as const){
        f.sqlite.prepare("UPDATE document_versions SET extraction_status=? WHERE id=?")
          .run(processingStatus,first.versionId);
        const replay=await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
        expect(replay.status).toBe(200);
        expect(await replay.json()).toMatchObject({
          documentId:first.documentId,versionId:first.versionId,sha256:first.sha256,
          processingStatus,repeated:true,ingestStatus:"quarantined"
        });
      }
      expect(f.put).toHaveBeenCalledTimes(1);
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM document_versions").get())
        .toMatchObject({n:1});
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get())
        .toMatchObject({n:1});
    }finally{f.close();}
  });

  it("rejects altered content with the same idempotency key", async () => {
    const f=fixture();
    try {
      await handleDocumentRequest(post(), f.env, "alice","c_a","b_a");
      const changed=new TextEncoder().encode("%PDF-1.7\nDifferent document %%EOF");
      const response=await handleDocumentRequest(post("upload_req_123",changed),f.env,"alice","c_a","b_a");
      expect(response.status).toBe(409);
      expect(f.put).toHaveBeenCalledTimes(1);
    } finally {f.close();}
  });

  it("hides a batch from users of other commissions and prevents observer writes", async () => {
    const f=fixture();
    try {
      expect((await handleDocumentRequest(post(),f.env,"bob","c_a","b_a")).status).toBe(404);
      expect((await handleDocumentRequest(post(),f.env,"viewer","c_a","b_a")).status).toBe(403);
      expect(f.put).not.toHaveBeenCalled();
    } finally {f.close();}
  });

  it("refuses cross-site browser uploads",async()=>{
    const f=fixture();
    try {
      expect((await handleDocumentRequest(post("upload_req_123",bytes,{Origin:"https://evil.test"}),f.env,"alice","c_a","b_a")).status).toBe(403);
    } finally {f.close();}
  });

  it("returns a service error without persisting when R2 fails", async () => {
    const f=fixture();
    try {
      f.put.mockRejectedValueOnce(new Error("R2 unavailable"));
      const response=await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
      expect(response.status).toBe(503);
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM documents").get()).toMatchObject({n:0});
    } finally {f.close();}
  });

  it("does not leave an object when the database transaction fails", async () => {
    const f=fixture();
    try {
      f.sqlite.exec("DROP TABLE audit_events");
      const response=await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
      expect(response.status).toBe(503);
      expect(f.put).toHaveBeenCalledTimes(1);
      expect(f.del).toHaveBeenCalledTimes(1);
      expect(f.objects.size).toBe(0);
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM documents").get()).toMatchObject({n:0});
    } finally {f.close();}
  });

  it("never returns full object keys from the document listing", async () => {
    const f=fixture();
    try {
      await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
      const response=await handleDocumentRequest(new Request(url),f.env,"alice","c_a","b_a");
      expect(JSON.stringify(await response.json())).not.toContain("quarantine/");
    } finally {f.close();}
  });
});
