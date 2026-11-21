import { describe, expect, it, vi } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { persistDocumentUpload } from "@folio/data";
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
  return {...f, objects, put, del, env: {
    DB:f.db, DOCUMENTS:bucket as unknown as R2Bucket,
    DOCUMENT_UPLOADS_ENABLED:"true" // Synthetic route-unit fixture only.
  }};
}
function post(key = "upload_req_123", data: Uint8Array = bytes, extras: Record<string,string> = {}) {
  return new Request(url, { method:"POST", headers:{
    "Content-Type":"application/pdf", "X-Document-Filename":"Contrato.pdf", "Idempotency-Key":key, ...extras
  }, body: data as BodyInit });
}

/** Replays real SQLite rows before interleaving a membership/commission update. */
function afterDocumentRead(db:D1Database, scope:"list"|"replay", mutate:()=>void):D1Database {
  const marker = scope==="list"
    ? "SELECT d.id, d.filename, v.id AS versionId"
    : "SELECT d.id AS documentId, v.id AS versionId";
  let fired=false;
  return {
    prepare(sql:string) {
      const statement=db.prepare(sql);
      if(!sql.includes(marker)) return statement;
      return {
        bind(...params:unknown[]) {
          const bound=statement.bind(...params);
          return scope==="list" ? {
            async all<T>() {
              const data=await bound.all<T>();
              if(!fired){fired=true;mutate();}
              return data;
            }
          } : {
            async first<T>() {
              const data=await bound.first<T>();
              if(!fired){fired=true;mutate();}
              return data;
            }
          };
        }
      } as unknown as D1PreparedStatement;
    }
  } as D1Database;
}

describe("authenticated PDF intake route", () => {
  it("never returns a document listing after membership is revoked during its D1 fetch",async()=>{
    const f=fixture();
    try {
      expect((await handleDocumentRequest(post(),f.env,"alice","c_a","b_a")).status).toBe(201);
      const before=f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get();
      const raced=afterDocumentRead(f.db,"list",()=>{
        f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
      });
      const res=await handleDocumentRequest(new Request(url),{...f.env,DB:raced},"alice","c_a","b_a");
      expect(res.status).toBe(404);
      expect(await res.json()).toEqual({error:"Not found"});
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual(before);
    }finally{f.close();}
  });

  it.each(["revoked","closed","observer"] as const)(
    "never confirms a retried upload after authority becomes %s during the D1 lookup",async (change)=>{
      const f=fixture();
      try {
        const created=await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
        expect(created.status).toBe(201);
        const before=f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get();
        const raced=afterDocumentRead(f.db,"replay",()=>{
          if(change==="revoked") {
            f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
          }else if(change==="closed") {
            f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
          }else{
            f.sqlite.exec("UPDATE commission_members SET role='observer' WHERE commission_id='c_a' AND subject='alice'");
          }
        });
        const res=await handleDocumentRequest(post(),{...f.env,DB:raced},"alice","c_a","b_a");
        expect(res.status).toBe(change==="revoked"?404:change==="closed"?409:403);
        expect(res.headers.get("Cache-Control")).toBe("no-store");
        expect(f.put).toHaveBeenCalledTimes(1);
        expect(f.sqlite.prepare("SELECT count(*) AS n FROM documents").get()).toEqual({n:1});
        expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual(before);
      }finally{f.close();}
    }
  );

  it("keeps read-only document listing available to active members of closed commissions",async()=>{
    const f=fixture();
    try{
      expect((await handleDocumentRequest(post(),f.env,"alice","c_a","b_a")).status).toBe(201);
      f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
      const res=await handleDocumentRequest(new Request(url),f.env,"alice","c_a","b_a");
      expect(res.status).toBe(200);
      expect(await res.json()).toHaveLength(1);
    }finally{f.close();}
  });


  it.each(["list","replay"] as const)(
    "fails closed if the final %s authorization probe loses D1 connectivity",async(mode)=>{
      const f=fixture();
      try {
        expect((await handleDocumentRequest(post(),f.env,"alice","c_a","b_a")).status).toBe(201);
        let accessReads=0;
        const broken={
          prepare(sql:string){
            if(sql.includes("SELECT m.role, c.status AS commissionStatus") && ++accessReads===2){
              throw new Error("PRIVATE_D1_DETAILS");
            }
            return f.db.prepare(sql);
          }
        } as D1Database;
        const res=await handleDocumentRequest(mode==="list"?new Request(url):post(),
          {...f.env,DB:broken},"alice","c_a","b_a");
        expect(res.status).toBe(503);
        expect(await res.json()).toEqual({error:"Request could not be completed"});
        expect(res.headers.get("Cache-Control")).toBe("no-store");
      }finally{f.close();}
    }
  );

  it("revalidates the winner after deleting an R2 object from a losing concurrent upload",async()=>{
    const f=fixture();
    try{
      f.put.mockImplementationOnce(async(key,data)=>{
        const sha=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",new Uint8Array(data).buffer)))
          .map(v=>v.toString(16).padStart(2,"0")).join("");
        f.objects.set("quarantine/winner.pdf",data);
        await persistDocumentUpload(f.db,{
          commissionId:"c_a",batchId:"b_a",subject:"alice",documentId:"winning_doc",
          versionId:"winning_ver",sha256:sha,r2Key:"quarantine/winner.pdf",
          filename:"Contrato.pdf",idempotencyKey:"upload_req_123"
        });
        f.objects.set(key,data);
        return {key};
      });
      f.del.mockImplementationOnce(async key=>{
        f.objects.delete(key);
        f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
      });
      const response=await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual({error:"Not found"});
      expect(f.put).toHaveBeenCalledTimes(1);
      expect(f.del).toHaveBeenCalledTimes(1);
      expect(f.objects.size).toBe(1);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM documents").get()).toEqual({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:1});
    }finally{f.close();}
  });

  it.each(["revoked","closed","observer"] as const)(
    "does not acknowledge a committed PDF upload when authority becomes %s before the HTTP response",
    async(change)=>{
      const f=fixture();
      try{
        let mutated=false;
        const raced={
          prepare:f.db.prepare.bind(f.db),
          async batch(statements:D1PreparedStatement[]){
            const rows=await f.db.batch(statements);
            mutated=true;
            if(change==="revoked"){
              f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
            }else if(change==="closed"){
              f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
            }else{
              f.sqlite.exec("UPDATE commission_members SET role='observer' WHERE commission_id='c_a' AND subject='alice'");
            }
            return rows;
          }
        } as D1Database;
        const result=await handleDocumentRequest(post(),{...f.env,DB:raced},"alice","c_a","b_a");
        expect(mutated).toBe(true);
        expect(result.status).toBe(change==="revoked"?404:change==="closed"?409:403);
        expect(result.headers.get("Cache-Control")).toBe("no-store");
        // Commit already occurred; never remove the R2 object it references.
        expect(f.put).toHaveBeenCalledTimes(1);
        expect(f.del).not.toHaveBeenCalled();
        expect(f.objects.size).toBe(1);
        for(const table of ["documents","document_versions","audit_events","document_processing_outbox"]){
          expect(f.sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get()).toEqual({n:1});
        }
      }finally{f.close();}
    }
  );

  it("does not clean a committed R2 object if the final D1 authorization check fails",async()=>{
    const f=fixture();
    try {
      let committed=false;
      const raced={
        prepare(sql:string){
          if(committed && sql.includes("SELECT m.role, c.status AS commissionStatus")){
            throw new Error("PRIVATE_D1_AFTER_COMMIT");
          }
          return f.db.prepare(sql);
        },
        async batch(statements:D1PreparedStatement[]){
          const result=await f.db.batch(statements);
          committed=true;
          return result;
        }
      } as D1Database;
      const response=await handleDocumentRequest(post(),{...f.env,DB:raced},"alice","c_a","b_a");
      expect(committed).toBe(true);
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({error:"Request could not be completed"});
      expect(f.del).not.toHaveBeenCalled();
      expect(f.objects.size).toBe(1);
      for(const table of ["documents","document_versions","audit_events","document_processing_outbox"]){
        expect(f.sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get()).toEqual({n:1});
      }
    }finally{f.close();}
  });

  it("retains its own committed R2 object if the D1 batch acknowledgement is lost",async()=>{
    const f=fixture();
    try{
      let committed=false;
      const raced={
        prepare:f.db.prepare.bind(f.db),
        async batch(statements:D1PreparedStatement[]){
          await f.db.batch(statements);
          committed=true;
          throw new Error("D1_ACK_LOST_AFTER_COMMIT");
        }
      } as unknown as D1Database;
      const response=await handleDocumentRequest(post(),{...f.env,DB:raced},"alice","c_a","b_a");
      expect(committed).toBe(true);
      expect(response.status).toBe(201);
      expect(await response.json()).toMatchObject({repeated:false,ingestStatus:"quarantined",processingStatus:"pending"});
      expect(f.del).not.toHaveBeenCalled();
      expect(f.objects.size).toBe(1);
      for(const table of ["documents","document_versions","audit_events","document_processing_outbox"]){
        expect(f.sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get()).toEqual({n:1});
      }
      const key=f.sqlite.prepare("SELECT r2_object_key AS objectKey FROM document_versions").get() as {objectKey:string};
      expect(f.objects.has(key.objectKey)).toBe(true);
    }finally{f.close();}
  });

  it("never deletes an uncertain committed R2 object when D1 recovery is unavailable",async()=>{
    const f=fixture();
    try{
      let committed=false;
      const raced={
        prepare(sql:string){
          if(committed && sql.includes("SELECT d.id AS documentId, v.id AS versionId")){
            throw new Error("D1_RECOVERY_UNAVAILABLE");
          }
          return f.db.prepare(sql);
        },
        async batch(statements:D1PreparedStatement[]){
          await f.db.batch(statements);
          committed=true;
          throw new Error("D1_ACK_LOST_AFTER_COMMIT");
        }
      } as unknown as D1Database;
      const response=await handleDocumentRequest(post(),{...f.env,DB:raced},"alice","c_a","b_a");
      expect(committed).toBe(true);
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({error:"Unable to register document"});
      expect(f.del).not.toHaveBeenCalled();
      const key=f.sqlite.prepare("SELECT r2_object_key AS objectKey FROM document_versions").get() as {objectKey:string};
      expect(f.objects.has(key.objectKey)).toBe(true);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_outbox").get()).toEqual({n:1});
    }finally{f.close();}
  });

  it("retains the committed PDF when the actor is revoked before a recovery lookup",async()=>{
    const f=fixture();
    try{
      let committed=false;
      const raced={
        prepare:f.db.prepare.bind(f.db),
        async batch(statements:D1PreparedStatement[]){
          await f.db.batch(statements);
          committed=true;
          f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
          throw new Error("D1_ACK_LOST_AFTER_REVOKED_COMMIT");
        }
      } as unknown as D1Database;
      const response=await handleDocumentRequest(post(),{...f.env,DB:raced},"alice","c_a","b_a");
      expect(committed).toBe(true);
      expect(response.status).toBe(503);
      expect(f.del).not.toHaveBeenCalled();
      const key=f.sqlite.prepare("SELECT r2_object_key AS objectKey FROM document_versions").get() as {objectKey:string};
      expect(f.objects.has(key.objectKey)).toBe(true);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:1});
    }finally{f.close();}
  });

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

  it("returns the winning state and cleans only the losing R2 object during a concurrent retry",async()=>{
    const f=fixture();
    try {
      f.put.mockImplementationOnce(async (key,data)=>{
        const digest=new Uint8Array(await crypto.subtle.digest(
          "SHA-256",new Uint8Array(data).buffer
        ));
        const sha256=Array.from(digest,byte=>byte.toString(16).padStart(2,"0")).join("");
        const winnerKey="quarantine/winner.pdf";
        f.objects.set(winnerKey,data);
        await persistDocumentUpload(f.db,{
          commissionId:"c_a",batchId:"b_a",subject:"alice",documentId:"doc_winner",
          versionId:"ver_winner",sha256,r2Key:winnerKey,filename:"Contrato.pdf",
          idempotencyKey:"upload_req_123"
        });
        f.sqlite.exec("UPDATE document_versions SET extraction_status='needs_review' WHERE id='ver_winner'");
        f.objects.set(key,data);
        return {key};
      });
      const replay=await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
      expect(replay.status).toBe(200);
      expect(await replay.json()).toMatchObject({
        documentId:"doc_winner",versionId:"ver_winner",
        ingestStatus:"quarantined",processingStatus:"needs_review",repeated:true
      });
      expect(f.put).toHaveBeenCalledTimes(1);
      expect(f.del).toHaveBeenCalledTimes(1);
      expect(f.objects.size).toBe(1);
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM documents").get()).toMatchObject({n:1});
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get()).toMatchObject({n:1});
      expect(f.sqlite.prepare(
        "SELECT COUNT(*) AS n FROM document_versions WHERE extraction_status='needs_review'"
      ).get()).toMatchObject({n:1});
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

  it("retains quarantine for audit when the D1 commit outcome cannot be proven", async () => {
    const f=fixture();
    try {
      f.sqlite.exec("DROP TABLE audit_events");
      const response=await handleDocumentRequest(post(),f.env,"alice","c_a","b_a");
      expect(response.status).toBe(503);
      expect(f.put).toHaveBeenCalledTimes(1);
      // The route cannot prove the transaction rolled back from a generic
      // D1 rejection. Keep the object for bounded quarantine reconciliation
      // instead of risking deletion of a committed document's R2 source.
      expect(f.del).not.toHaveBeenCalled();
      expect(f.objects.size).toBe(1);
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
