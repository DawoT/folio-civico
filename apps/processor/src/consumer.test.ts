import {describe,expect,it,vi} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {persistDocumentUpload} from "../../../packages/data/src/documents";
import {serializeInspectionManifest,type InspectedTextManifest} from "../../../packages/data/src/inspected-text";
import {processProcessingMessage,processBatch} from "./consumer";

const original=new TextEncoder().encode("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
const scannerSecret="test-processing-key-".repeat(3);
async function sha256(bytes:Uint8Array):Promise<string>{
 const hash=await crypto.subtle.digest("SHA-256",new Uint8Array(bytes).buffer);
 return [...new Uint8Array(hash)].map(n=>n.toString(16).padStart(2,"0")).join("");
}
async function signed(manifest:InspectedTextManifest):Promise<string>{
 const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(scannerSecret),
  {name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const bytes=await crypto.subtle.sign("HMAC",key,new Uint8Array(serializeInspectionManifest(manifest)).buffer);
 return [...new Uint8Array(bytes)].map(n=>n.toString(16).padStart(2,"0")).join("");
}
async function fixture(){
 const f=makeD1();
 f.sqlite.exec(`
 INSERT INTO commissions(id,name,status) VALUES('c_a','Synthetic','active');
 INSERT INTO commission_members(commission_id,subject,role) VALUES('c_a','reviewer','member');
 INSERT INTO document_batches(id,commission_id,label) VALUES('b_a','c_a','Documents');
 `);
 const sha=await sha256(original);
 await persistDocumentUpload(f.db,{
  commissionId:"c_a",batchId:"b_a",subject:"reviewer",
  documentId:"doc_a",versionId:"ver_a",sha256:sha,r2Key:"quarantine/opaque-doc.pdf",
  filename:"synthetic.pdf",idempotencyKey:"processing_intake_0001"
 });
 const manifest:InspectedTextManifest={
  documentVersionId:"ver_a",sourceSha256:sha,scanVerdict:"clean",
  scanner:"isolated-scanner-v1",scannerReportId:"test_report_123456",
  scannedAt:"2026-11-18T17:30:00.000Z",
  pages:[{page:1,text:"Expediente verificado para prueba"}]
 };
 const get=vi.fn(async(_key:string)=>({
  size:original.byteLength,
  arrayBuffer:async()=>original.buffer.slice(original.byteOffset,original.byteOffset+original.byteLength)
 }));
 const inspectorFetch=vi.fn(async(_input:Request|string)=>Response.json({
  manifest,signature:await signed(manifest)
 }));
 const env={
  DB:f.db,DOCUMENTS:{get} as unknown as R2Bucket,
  INSPECTOR:{fetch:inspectorFetch} as unknown as Fetcher,
  INSPECTOR_SERVICE_TOKEN:"test-service-token-".repeat(3),
  INSPECTOR_HMAC_KEY:scannerSecret
 };
 return {...f,sha,manifest,get,inspectorFetch,env};
}
const message=(sha:string)=>({kind:"folio.process.pdf" as const,versionId:"ver_a",sourceSha256:sha});
describe("Cloudflare Queue inspection consumer",()=>{
 it("does not send original to inspector when commission closes during R2 retrieval",async()=>{
  const f=await fixture();
  try{
   f.get.mockImplementationOnce(async()=>{
    f.sqlite.prepare("UPDATE commissions SET status='closed' WHERE id='c_a'").run();
    return {size:original.byteLength,arrayBuffer:async()=>
      original.buffer.slice(original.byteOffset,original.byteOffset+original.byteLength)};
   });
   expect(await processProcessingMessage(message(f.sha),f.env)).toBe("stale");
   expect(f.inspectorFetch).not.toHaveBeenCalled();
   expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions WHERE id='ver_a'").get())
    .toMatchObject({extraction_status:"pending"});
  }finally{f.close();}
 });
 it("does not persist 422 unsafe status or audit when commission closes during inspection",async()=>{
  const f=await fixture();
  try{
   f.inspectorFetch.mockImplementationOnce(async()=>{
    f.sqlite.prepare("UPDATE commissions SET status='closed' WHERE id='c_a'").run();
    return new Response(null,{status:422});
   });
   expect(await processProcessingMessage(message(f.sha),f.env)).toBe("stale");
   expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions WHERE id='ver_a'").get())
    .toMatchObject({extraction_status:"pending"});
   expect(f.sqlite.prepare(
    "SELECT count(*) AS n FROM audit_events WHERE action='document.inspection_rejected'"
   ).get()).toMatchObject({n:0});
  }finally{f.close();}
 });
 it("does not admit clean signed report when commission closes during inspection",async()=>{
  const f=await fixture();
  try{
   f.inspectorFetch.mockImplementationOnce(async()=>{
    f.sqlite.prepare("UPDATE commissions SET status='closed' WHERE id='c_a'").run();
    return Response.json({manifest:f.manifest,signature:await signed(f.manifest)});
   });
   expect(await processProcessingMessage(message(f.sha),f.env)).toBe("stale");
   expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions WHERE id='ver_a'").get())
    .toMatchObject({extraction_status:"pending"});
   expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
    .toMatchObject({n:0});
   expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_pages").get())
    .toMatchObject({n:0});
  }finally{f.close();}
 });
 it("rejects SQL report and 422 status writes after the commission closes",async()=>{
  const f=await fixture();
  try{
   f.sqlite.prepare("UPDATE commissions SET status='closed' WHERE id='c_a'").run();
   expect(()=>f.sqlite.prepare(`
    INSERT INTO document_processing_reports(
      document_version_id,scanner_name,scanner_report_id,scanned_at,
      source_sha256,manifest_sha256,page_count
    ) VALUES('ver_a','scanner','report_closed_commission_001',
      '2026-11-19T16:00:00.000Z',?,?,1)
   `).run(f.sha,f.sha)).toThrow(/PROCESSING_COMMISSION_CLOSED/);
   expect(()=>f.sqlite.prepare(`
    UPDATE document_versions SET extraction_status='needs_review'
    WHERE id='ver_a'
   `).run()).toThrow(/PROCESSING_COMMISSION_CLOSED/);
  }finally{f.close();}
 });
 it("cannot create a late 422 audit for a closed commission if status already changed",async()=>{
  const f=await fixture();
  try{
   f.inspectorFetch.mockResolvedValueOnce(new Response(null,{status:422}));
   let raced=false;
   const db={
    prepare:f.db.prepare.bind(f.db),
    batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
     if(!raced){
      raced=true;
      f.sqlite.prepare(
       "UPDATE document_versions SET extraction_status='needs_review' WHERE id='ver_a'"
      ).run();
      f.sqlite.prepare("UPDATE commissions SET status='closed' WHERE id='c_a'").run();
     }
     return f.db.batch(statements);
    }
   } as unknown as D1Database;
   expect(await processProcessingMessage(message(f.sha),{...f.env,DB:db})).toBe("stale");
   expect(raced).toBe(true);
   expect(f.sqlite.prepare(
     "SELECT count(*) AS n FROM audit_events WHERE action='document.inspection_rejected'"
   ).get()).toMatchObject({n:0});
  }finally{f.close();}
 });
 it.each(["unsafe","clean"] as const)(
  "blocks a %s result if commission closes between preflight and atomic DB batch",
  async(verdict)=>{
   const f=await fixture();
   try{
    if(verdict==="unsafe"){
     f.inspectorFetch.mockResolvedValueOnce(new Response(null,{status:422}));
    }
    let raced=false;
    const db={
      prepare:f.db.prepare.bind(f.db),
      batch:async(statements:Parameters<D1Database["batch"]>[0])=>{
       if(!raced){
        raced=true;
        f.sqlite.prepare("UPDATE commissions SET status='closed' WHERE id='c_a'").run();
       }
       return f.db.batch(statements);
      }
    } as unknown as D1Database;
    expect(await processProcessingMessage(message(f.sha),{...f.env,DB:db})).toBe("stale");
    expect(raced).toBe(true);
    expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions WHERE id='ver_a'").get())
     .toMatchObject({extraction_status:"pending"});
    expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
     .toMatchObject({n:0});
    expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_pages").get())
     .toMatchObject({n:0});
    expect(f.sqlite.prepare(
     "SELECT count(*) AS n FROM audit_events WHERE action IN ('document.inspection_rejected','document.inspected_text_admitted')"
    ).get()).toMatchObject({n:0});
   }finally{f.close();}
  }
 );

 it("verifies the Python inspector HMAC protocol with non-ASCII page text",async()=>{
   const vector:InspectedTextManifest={
     documentVersionId:"test_ver_1",
     sourceSha256:"a".repeat(64),
     scanVerdict:"clean",
     scanner:"folio-isolated-clamav-poppler-v1",
     scannerReportId:"scan_123456789",
     scannedAt:"2026-11-18T17:30:00.000Z",
     pages:[{page:1,text:"Órdenes de compra — obra Código 01"}]
   };
   // Independent golden signature generated by Python hmac/json.dumps.
   const expected="db780f659b237992a32d3b78ea3318b6001df6e013ce6ce51026cd7dcd160ca9";
   const key=await crypto.subtle.importKey("raw",new TextEncoder().encode("synthetic".repeat(6)),
      {name:"HMAC",hash:"SHA-256"},false,["sign"]);
   const digest=await crypto.subtle.sign("HMAC",key,new Uint8Array(serializeInspectionManifest(vector)).buffer);
   const signature=[...new Uint8Array(digest)].map(n=>n.toString(16).padStart(2,"0")).join("");
   expect(signature).toBe(expected);
 });
 it("hands the original only to an internal inspector binding and admits signed pages",async()=>{
  const f=await fixture();
  try{
   const result=await processProcessingMessage(message(f.sha),f.env);
   expect(result).toBe("completed");
   expect(f.inspectorFetch).toHaveBeenCalledOnce();
   const request=f.inspectorFetch.mock.calls[0]?.[0] as Request;
   expect(request.headers.get("X-Folio-Inspector-Token")).toBe(f.env.INSPECTOR_SERVICE_TOKEN);
   expect(request.headers.get("X-Folio-Document-Version")).toBe("ver_a");
   expect(request.headers.get("X-Folio-Source-Sha256")).toBe(f.sha);
   expect(new Uint8Array(await request.arrayBuffer())).toEqual(original);
   expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions WHERE id='ver_a'").get())
    .toMatchObject({extraction_status:"ready"});
   expect(f.sqlite.prepare("SELECT state FROM document_processing_outbox").get())
    .toMatchObject({state:"completed"});
   expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:2});
  }finally{f.close();}
 });
 it("acks duplicate processing without recontacting the scanner",async()=>{
  const f=await fixture();
  try{
   expect(await processProcessingMessage(message(f.sha),f.env)).toBe("completed");
   expect(await processProcessingMessage(message(f.sha),f.env)).toBe("already_done");
   expect(f.inspectorFetch).toHaveBeenCalledOnce();
  }finally{f.close();}
 });
 it("fails closed if scanner credentials or binding are absent",async()=>{
  const f=await fixture();
  try{
   await expect(processProcessingMessage(message(f.sha),{
    ...f.env,INSPECTOR:undefined
   })).rejects.toThrow();
   await expect(processProcessingMessage(message(f.sha),{
    ...f.env,INSPECTOR_HMAC_KEY:""
   })).rejects.toThrow();
   expect(f.inspectorFetch).not.toHaveBeenCalled();
   expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions").get())
    .toMatchObject({extraction_status:"pending"});
  }finally{f.close();}
 });
 it("rejects mismatched queue hash before reading R2",async()=>{
  const f=await fixture();
  try{
   expect(await processProcessingMessage(message("f".repeat(64)),f.env)).toBe("stale");
   expect(f.get).not.toHaveBeenCalled();
  }finally{f.close();}
 });
 it("never promotes unsigned or invalid scanner results",async()=>{
  const f=await fixture();
  try{
   f.inspectorFetch.mockResolvedValueOnce(Response.json({
    manifest:f.manifest,signature:"0".repeat(64)
   }));
   await expect(processProcessingMessage(message(f.sha),f.env)).rejects.toThrow();
   expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions").get())
    .toMatchObject({extraction_status:"pending"});
   expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_pages").get()).toMatchObject({n:0});
  }finally{f.close();}
 });
 it("routes explicit malware/unsafe verdict to needs_review without ready pages",async()=>{
  const f=await fixture();
  try{
   f.inspectorFetch.mockResolvedValueOnce(new Response(null,{status:422}));
   expect(await processProcessingMessage(message(f.sha),f.env)).toBe("needs_review");
   expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions").get())
    .toMatchObject({extraction_status:"needs_review"});
   expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_pages").get()).toMatchObject({n:0});
  }finally{f.close();}
 });
 it("retries only transient failures and acks poison messages independently",async()=>{
  const f=await fixture();
  try{
   f.inspectorFetch.mockRejectedValueOnce(new Error("Outage"));
   const retry=vi.fn(),ack=vi.fn();
   const malformedAck=vi.fn();
   const batch={
    queue:"folio-civico-pdf-pending",
    messages:[
     {body:{kind:"wrong"},ack:malformedAck,retry:vi.fn()},
     {body:message(f.sha),ack,retry}
    ]
   } as unknown as MessageBatch<unknown>;
   const result=await processBatch(batch,f.env);
   expect(result).toMatchObject({invalid:1,retried:1,acked:0});
   expect(malformedAck).toHaveBeenCalledOnce();
   expect(retry).toHaveBeenCalledOnce();
   expect(ack).not.toHaveBeenCalled();
  }finally{f.close();}
 });
});
