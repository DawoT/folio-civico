import {describe,expect,it,vi} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {persistDocumentUpload} from "@folio/data";
import {processProcessingMessage} from "../../processor/src/consumer";
import {handleInspectorGatewayRequest} from "./route";

const source=new TextEncoder().encode("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
const sampleServiceCredential="synthetic-service-sampleServiceCredential-".repeat(2);
const key="synthetic-hmac-key-".repeat(3);
const digest=async()=>Array.from(new Uint8Array(await crypto.subtle.digest(
 "SHA-256",new Uint8Array(source).buffer)))
 .map(b=>b.toString(16).padStart(2,"0")).join("");

async function fixture(){
 const f=makeD1();
 f.sqlite.exec(`
   INSERT INTO commissions(id,name,status) VALUES('c_a','Synthetic commission','active');
   INSERT INTO commission_members(commission_id,subject,role) VALUES('c_a','reviewer','member');
   INSERT INTO document_batches(id,commission_id,label) VALUES('b_a','c_a','Synthetic lot');
 `);
 const sha=await digest();
 await persistDocumentUpload(f.db,{
   commissionId:"c_a",batchId:"b_a",subject:"reviewer",
   documentId:"doc_01",versionId:"version_01",
   filename:"synthetic.pdf",sha256:sha,
   r2Key:"quarantine/private-opaque-name.pdf",idempotencyKey:"signed_pipeline_001"
 });
 const get=vi.fn(async()=>({size:source.length,arrayBuffer:async()=>new Uint8Array(source).buffer}));
 const mockContainer=vi.fn(async(_incoming:Request)=>Response.json({manifest:{
   documentVersionId:"version_01",sourceSha256:sha,scanVerdict:"clean",
   scanner:"isolated-scanner-v1",scannerReportId:"test_report_gateway_001",
   scannedAt:"2026-11-18T19:00:00.000Z",
   pages:[{page:1,text:"Texto inspeccionado de prueba"}]
 }}));
 const boundGateway={
   fetch:(request:Request)=>handleInspectorGatewayRequest(request,{
     INSPECTOR_SERVICE_TOKEN:sampleServiceCredential,INSPECTOR_HMAC_KEY:key
   },mockContainer)
 };
 const env={
   DB:f.db,DOCUMENTS:{get} as unknown as R2Bucket,
   INSPECTOR:boundGateway as unknown as Fetcher,
   INSPECTOR_SERVICE_TOKEN:sampleServiceCredential,INSPECTOR_HMAC_KEY:key
 };
 return {...f,sha,get,mockContainer,env};
}

describe("outbox -> Queue consumer -> gateway signer -> D1 admission",()=>{
 it("admits synthetic page text with an HMAC never held by the parser container",async()=>{
   const f=await fixture();
   try{
     const status=await processProcessingMessage({
       kind:"folio.process.pdf",versionId:"version_01",sourceSha256:f.sha
     },f.env);
     expect(status).toBe("completed");
     expect(f.mockContainer).toHaveBeenCalledOnce();
     const request=f.mockContainer.mock.calls[0]?.[0] as Request;
     expect(request.headers.get("X-Folio-Document-Version")).toBe("version_01");
     expect(request.headers.has("INSPECTOR_HMAC_KEY")).toBe(false);
     expect(new Uint8Array(await request.arrayBuffer())).toEqual(source);
     expect(f.sqlite.prepare("SELECT extraction_status,page_count FROM document_versions WHERE id='version_01'").get())
       .toMatchObject({extraction_status:"ready",page_count:1});
     expect(f.sqlite.prepare("SELECT state FROM document_processing_outbox").get())
       .toMatchObject({state:"completed"});
     expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get())
       .toMatchObject({n:2});
   }finally{f.close();}
 });
 it("fails closed when a compromised parser returns a forged original hash",async()=>{
   const f=await fixture();
   try{
     f.mockContainer.mockResolvedValueOnce(Response.json({manifest:{
       documentVersionId:"version_01",sourceSha256:"f".repeat(64),
       scanVerdict:"clean",scanner:"isolated-scanner-v1",
       scannerReportId:"test_report_gateway_002",
       scannedAt:"2026-11-18T19:00:00.000Z",
       pages:[{page:1,text:"Spoofed"}]
     }}));
     await expect(processProcessingMessage({
       kind:"folio.process.pdf",versionId:"version_01",sourceSha256:f.sha
     },f.env)).rejects.toThrow();
     expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions WHERE id='version_01'").get())
       .toMatchObject({extraction_status:"pending"});
     expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
       .toMatchObject({n:0});
   }finally{f.close();}
 });
});
