import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {handleReviewRequest} from "./review-routes";

const url="https://folio.test/api/commissions/c_a/observations/page-drafts";
function fixture(ready:boolean) {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('c_a','A','active'),('c_b','B','active');
    INSERT INTO commission_members(commission_id,subject,role,active)
      VALUES('c_a','alice','member',1),('c_a','viewer','observer',1),('c_b','bob','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('b_a','c_a','Obras');
    INSERT INTO documents(id,commission_id,batch_id,filename) VALUES('doc_a','c_a','b_a','Expediente.pdf');
    INSERT INTO document_versions(id,document_id,version_number,sha256,r2_object_key)
      VALUES('ver_a','doc_a',1,'${"a".repeat(64)}','quarantine/secret.pdf');
  `);
  if(ready)f.sqlite.exec(`
    INSERT INTO document_processing_reports(document_version_id,scanner_name,scanner_report_id,
      scanned_at,source_sha256,manifest_sha256,page_count)
      VALUES('ver_a','isolated-scanner','report_synthetic_001','2026-11-18T17:30:00.000Z',
      '${"a".repeat(64)}','${"b".repeat(64)}',1);
    INSERT INTO document_pages(document_version_id,page,extracted_text,extraction_status)
      VALUES('ver_a',1,'Texto de la página inspeccionada','ready');
    UPDATE document_versions SET extraction_status='ready',page_count=1 WHERE id='ver_a';
  `);
  return f;
}
const payload={title:"Evidencia en expediente",description:"El revisor observó el texto en la página.",
  documentVersionId:"ver_a",page:1};
function request(value:unknown=payload,key="page_review_key_0001") {
  return new Request(url,{method:"POST",headers:{"Content-Type":"application/json",
    "Idempotency-Key":key},body:JSON.stringify(value)});
}
describe("human page evidence observation",()=>{
  it("derives immutable page SHA from D1 rather than accepting it from browser",async()=>{
    const f=fixture(true);
    try {
      const res=await handleReviewRequest(request(),{DB:f.db},"alice","c_a","page-drafts");
      expect(res.status).toBe(201);
      const saved=await res.json() as {evidence:unknown[];status:string};
      expect(saved.status).toBe("draft");
      expect(saved.evidence).toEqual([{
        type:"DOCUMENT_PAGE",commissionId:"c_a",documentVersionId:"ver_a",
        page:1,sha256:"a".repeat(64)
      }]);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:1});
      const again=await handleReviewRequest(request(),{DB:f.db},"alice","c_a","page-drafts");
      expect(again.status).toBe(200);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM observations").get()).toMatchObject({n:1});
    }finally{f.close();}
  });
  it("rejects pending or out-of-range pages, and cross-commission or observer writes",async()=>{
    const pending=fixture(false);
    const ready=fixture(true);
    try{
      expect((await handleReviewRequest(request(),{DB:pending.db},"alice","c_a","page-drafts")).status).toBe(422);
      expect((await handleReviewRequest(request({...payload,page:3}),{DB:ready.db},"alice","c_a","page-drafts")).status).toBe(422);
      expect((await handleReviewRequest(request(),{DB:ready.db},"bob","c_a","page-drafts")).status).toBe(404);
      expect((await handleReviewRequest(request(),{DB:ready.db},"viewer","c_a","page-drafts")).status).toBe(403);
      expect(ready.sqlite.prepare("SELECT count(*) AS n FROM observations").get()).toMatchObject({n:0});
    }finally{pending.close();ready.close();}
  });
  it("refuses forged SHA, forged reviewer, unexpected fields and conflicting keys",async()=>{
    const f=fixture(true);
    try {
      expect((await handleReviewRequest(request({...payload,sha256:"a".repeat(64)}),{DB:f.db},"alice","c_a","page-drafts")).status).toBe(400);
      expect((await handleReviewRequest(request({...payload,reviewerId:"alice"}),{DB:f.db},"alice","c_a","page-drafts")).status).toBe(400);
      await handleReviewRequest(request(),{DB:f.db},"alice","c_a","page-drafts");
      expect((await handleReviewRequest(request({...payload,title:"Otro título"}),{DB:f.db},"alice","c_a","page-drafts")).status).toBe(409);
    }finally{f.close();}
  });
});
