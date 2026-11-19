import { afterEach, describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleApiRequest, type ApiEnv } from "./index";
import {
  auditProcessingBacklog, auditQuarantine, dispatchProcessingOutbox,
  type InspectedTextManifest, type ProcessingQueueMessage
} from "@folio/data";
import { processBatch, type ProcessorEnv } from "../../processor/src/consumer";
import { handleInspectorGatewayRequest } from "../../inspector-gateway/src/route";

const ISSUER="https://pipeline-local.cloudflareaccess.com";
const AUDIENCE="folio-pipeline-e2e";
const SERVICE_TOKEN="isolated-pipeline-service-token-".repeat(2);
const HMAC_KEY="isolated-pipeline-hmac-key-".repeat(2);
const PDF=new TextEncoder().encode("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF");
const DATE="2026-11-19T12:00:00.000Z";
const PREFIX="/api/commissions/c_a";
const DOCS=PREFIX+"/batches/b_a/documents";

type R2Item={bytes:Uint8Array;uploaded:Date;sha256:string};
afterEach(()=>vi.unstubAllGlobals());

async function fixture(){
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('c_a','Comisión E2E','active'),('c_b','Comisión ajena','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('c_a','author','member',1),('c_a','reviewer','member',1),
      ('c_a','revoked','member',0),('c_b','outsider','member',1);
    INSERT INTO document_batches(id,commission_id,label)
      VALUES('b_a','c_a','Lote PDF sintético');
  `);
  const objects=new Map<string,R2Item>();
  const put=vi.fn(async(key:string,value:Uint8Array,opts?:{customMetadata?:{sha256?:string}})=>{
    objects.set(key,{bytes:new Uint8Array(value),uploaded:new Date("2026-11-18T00:00:00.000Z"),
      sha256:opts?.customMetadata?.sha256??""});
    return {key};
  });
  const get=vi.fn(async(key:string)=>{
    const item=objects.get(key);
    return item?{
      size:item.bytes.byteLength,
      arrayBuffer:async()=>item.bytes.slice().buffer
    }:null;
  });
  const del=vi.fn(async(key:string)=>{objects.delete(key);});
  const head=vi.fn(async(key:string)=>{
    const item=objects.get(key);
    return item?{key,size:item.bytes.byteLength,uploaded:item.uploaded,
      customMetadata:{sha256:item.sha256}}:null;
  });
  const list=vi.fn(async()=>{
    const entries=[...objects].map(([key,obj])=>({
      key,size:obj.bytes.byteLength,uploaded:obj.uploaded,
      customMetadata:{sha256:obj.sha256}
    }));
    return {objects:entries,truncated:false};
  });
  const bucket={put,get,delete:del,head,list} as unknown as R2Bucket;
  const {privateKey,publicKey}=await generateKeyPair("RS256");
  const jwk=await exportJWK(publicKey);
  jwk.kid="local-e2e-tenant-key";
  const jwks=vi.fn(async()=>Response.json({keys:[jwk]}));
  vi.stubGlobal("fetch",jwks);
  const token=async(subject:string)=>new SignJWT({kind:"synthetic"})
    .setProtectedHeader({alg:"RS256",kid:jwk.kid})
    .setIssuer(ISSUER).setAudience(AUDIENCE).setSubject(subject)
    .setIssuedAt().setExpirationTime("10m").sign(privateKey);
  const apiEnv:ApiEnv={DB:f.db,DOCUMENTS:bucket,ACCESS_TEAM_DOMAIN:ISSUER,ACCESS_AUD:AUDIENCE};
  const call=async(subjectToken:string,path:string,method="GET",body?:Uint8Array|object,key?:string)=>{
    const pdf=body instanceof Uint8Array;
    return handleApiRequest(new Request("https://folio.local"+path,{
      method,headers:{
        "Cf-Access-Jwt-Assertion":subjectToken,
        ...(body?{"Content-Type":pdf?"application/pdf":"application/json"}:{}),
        ...(pdf?{"X-Document-Filename":"sintetico.pdf"}:{}),
        ...(key?{"Idempotency-Key":key}:{})
      },...(body?{body:pdf?body as BodyInit:JSON.stringify(body)}:{})
    }),apiEnv);
  };

  const queued:ProcessingQueueMessage[]=[];
  let queueFailed=false;
  const send=vi.fn(async(message:ProcessingQueueMessage)=>{
    if(queueFailed)throw new Error("synthetic queue outage");
    queued.push(structuredClone(message));
  });
  const queue={send} as unknown as Queue<ProcessingQueueMessage>;
  const seenUnsigned:InspectedTextManifest[]=[];
  const forward=vi.fn(async(request:Request)=>{
    const bytes=new Uint8Array(await request.arrayBuffer());
    expect(bytes).toEqual(PDF);
    expect(request.headers.get("X-Folio-Inspector-Token")).toBe(SERVICE_TOKEN);
    expect(request.headers.has("INSPECTOR_HMAC_KEY")).toBe(false);
    const report:InspectedTextManifest={
      documentVersionId:request.headers.get("X-Folio-Document-Version")!,
      sourceSha256:request.headers.get("X-Folio-Source-Sha256")!,
      scanVerdict:"clean",scanner:"synthetic-inspection-fixture",
      scannerReportId:"report_synthetic_001",
      scannedAt:DATE,pages:[
        {page:1,text:"Obra pública, folio uno — texto sintético"},
        {page:2,text:"Acta de inspección sintética, folio dos"}
      ]
    };
    seenUnsigned.push(report);
    return Response.json({manifest:report});
  });
  let responseTransform:(response:Response)=>Promise<Response>=async r=>r;
  const gatewayFetch=vi.fn(async(request:Request)=>{
    const res=await handleInspectorGatewayRequest(request,{
      INSPECTOR_SERVICE_TOKEN:SERVICE_TOKEN,INSPECTOR_HMAC_KEY:HMAC_KEY
    },forward);
    return responseTransform(res);
  });
  const processorEnv:ProcessorEnv={
    DB:f.db,DOCUMENTS:bucket,
    INSPECTOR:{fetch:gatewayFetch} as unknown as Fetcher,
    INSPECTOR_SERVICE_TOKEN:SERVICE_TOKEN,INSPECTOR_HMAC_KEY:HMAC_KEY
  };

  const deliver=async(messages:unknown[]=queued.splice(0))=>{
    const items=messages.map(body=>({
      body,ack:vi.fn(),retry:vi.fn()
    }));
    const result=await processBatch({
      queue:"folio-civico-pdf-pending",messages:items
    } as unknown as MessageBatch<unknown>,processorEnv);
    return {result,items};
  };
  const upload=async(subjectToken:string,key="synthetic-upload-e2e-0001")=>{
    const response=await call(subjectToken,DOCS,"POST",PDF,key);
    return {response,json:await response.json() as {
      documentId:string;versionId:string;sha256:string;
      ingestStatus:string;processingStatus:string;repeated:boolean
    }};
  };
  return {...f,objects,bucket,put,get,del,head,list,jwks,token,call,apiEnv,
    queue,send,queued,seenUnsigned,forward,gatewayFetch,processorEnv,upload,deliver,
    setQueueFailure(v:boolean){queueFailed=v;},
    setGatewayTransform(fn:(response:Response)=>Promise<Response>){responseTransform=fn;}
  };
}

describe("R2 · actual signed API intake → durable outbox → synthetic Queue → gateway HMAC → D1 pages",()=>{
  it("admits pages exactly once and exposes text only to active members after the gateway signs a clean manifest",async()=>{
    const f=await fixture();
    try {
      const author=await f.token("author");
      const reviewer=await f.token("reviewer");
      const outsider=await f.token("outsider");
      const ingested=await f.upload(author);
      expect(ingested.response.status).toBe(201);
      expect(ingested.json).toMatchObject({ingestStatus:"quarantined",processingStatus:"pending",repeated:false});
      expect(f.objects.size).toBe(1);
      expect(f.put).toHaveBeenCalledTimes(1);
      const duplicate=await f.upload(author);
      expect(duplicate.response.status).toBe(200);
      expect(duplicate.json).toMatchObject({versionId:ingested.json.versionId,repeated:true});
      expect(f.put).toHaveBeenCalledTimes(1);
      expect((await f.call(reviewer,PREFIX+"/documents/"+ingested.json.versionId+"/pages")).status).toBe(404);
      const pre=f.sqlite.prepare("SELECT state,attempts FROM document_processing_outbox").get();
      expect(pre).toMatchObject({state:"pending",attempts:0});

      const result=await dispatchProcessingOutbox(f.db,f.queue,new Date(DATE));
      expect(result).toEqual({selected:1,sent:1,failed:0});
      expect(f.send).toHaveBeenCalledWith({
        kind:"folio.process.pdf",versionId:ingested.json.versionId,
        sourceSha256:ingested.json.sha256
      });
      const sent=f.queued.splice(0);
      expect(JSON.stringify(sent)).not.toContain("quarantine/");
      expect(JSON.stringify(sent)).not.toContain("sintetico.pdf");
      expect(JSON.stringify(sent)).not.toContain("c_a");
      const delivered=await f.deliver(sent);
      expect(delivered.result).toEqual({acked:1,retried:0,invalid:0});
      expect(delivered.items[0]?.ack).toHaveBeenCalledOnce();
      expect(f.forward).toHaveBeenCalledOnce();
      expect(f.seenUnsigned).toHaveLength(1);
      expect(f.sqlite.prepare("SELECT state,attempts FROM document_processing_outbox").get())
        .toMatchObject({state:"completed",attempts:1});
      expect(f.sqlite.prepare("SELECT extraction_status AS status,page_count AS pages FROM document_versions").get())
        .toMatchObject({status:"ready",pages:2});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
        .toMatchObject({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get())
        .toMatchObject({n:2});

      const pages=await f.call(reviewer,PREFIX+"/documents/"+ingested.json.versionId+"/pages");
      expect(pages.status).toBe(200);
      expect(pages.headers.get("Cache-Control")).toContain("no-store");
      const body=await pages.json() as {versionId:string;sha256:string;pageCount:number;pages:Array<{page:number;text:string}>};
      expect(body).toMatchObject({versionId:ingested.json.versionId,sha256:ingested.json.sha256,pageCount:2});
      expect(body.pages.map(p=>p.page)).toEqual([1,2]);
      expect(JSON.stringify(body)).not.toContain("quarantine/");
      expect((await f.call(outsider,PREFIX+"/documents/"+ingested.json.versionId+"/pages")).status).toBe(404);
      expect((await f.call(reviewer,"/api/commissions/c_b/documents/"+ingested.json.versionId+"/pages")).status).toBe(404);

      const repeated=await f.deliver(sent);
      expect(repeated.result).toEqual({acked:1,retried:0,invalid:0});
      expect(f.forward).toHaveBeenCalledOnce();
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
        .toMatchObject({n:1});
      expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:16:00.000Z"))).selected).toBe(0);
      const audit=await auditQuarantine(f.db,f.bucket,{
        now:new Date("2026-11-22T12:00:00.000Z")
      });
      expect(audit).toMatchObject({referenced:1,orphanCandidates:0,missingObjects:0,
        integrityVerified:false,snapshotAtomic:false});
      expect(f.del).not.toHaveBeenCalled();
    } finally {f.close();}
  });

  it("does not mark an unavailable Queue as sent, retries gateway 503, then completes without duplicate reports",async()=>{
    const f=await fixture();
    try {
      const author=await f.token("author");
      const {json:created}=await f.upload(author);
      f.setQueueFailure(true);
      expect(await dispatchProcessingOutbox(f.db,f.queue,new Date(DATE)))
        .toEqual({selected:1,sent:0,failed:1});
      expect(f.sqlite.prepare("SELECT state,attempts FROM document_processing_outbox").get())
        .toMatchObject({state:"pending",attempts:0});
      f.setQueueFailure(false);
      expect((await dispatchProcessingOutbox(f.db,f.queue,new Date(DATE))).sent).toBe(1);
      const dispatched=f.queued.splice(0);
      f.forward.mockRejectedValueOnce(new Error("temporarily unavailable"));
      const first=await f.deliver(dispatched);
      expect(first.result).toEqual({acked:0,retried:1,invalid:0});
      expect(first.items[0]?.retry).toHaveBeenCalledOnce();
      expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions").get())
        .toMatchObject({extraction_status:"pending"});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
        .toMatchObject({n:0});
      // Short lease: no redelivery. Expired lease: at-least-once resend.
      expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:10:00.000Z"))).sent).toBe(0);
      expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:16:00.000Z"))).sent).toBe(1);
      const second=await f.deliver(f.queued.splice(0));
      expect(second.result).toEqual({acked:1,retried:0,invalid:0});
      expect(f.sqlite.prepare("SELECT state,attempts FROM document_processing_outbox").get())
        .toMatchObject({state:"completed",attempts:2});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
        .toMatchObject({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_pages").get())
        .toMatchObject({n:2});
      expect((await f.call(author,PREFIX+"/documents/"+created.versionId+"/pages")).status).toBe(200);
    }finally{f.close();}
  });

  it("keeps 422 in needs_review and never serves pages; invalid Queue messages are acknowledged without access to R2",async()=>{
    const f=await fixture();
    try{
      const author=await f.token("author");
      const uploaded=await f.upload(author);
      expect((await dispatchProcessingOutbox(f.db,f.queue,new Date(DATE))).sent).toBe(1);
      f.forward.mockResolvedValueOnce(new Response("bad PDF",{status:422}));
      const poison={kind:"folio.process.pdf",versionId:"bad!id",sourceSha256:"a".repeat(64)};
      const result=await f.deliver([poison,...f.queued.splice(0)]);
      expect(result.result).toEqual({acked:1,retried:0,invalid:1});
      expect(result.items[0]?.ack).toHaveBeenCalledOnce();
      expect(result.items[1]?.ack).toHaveBeenCalledOnce();
      expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions").get())
        .toMatchObject({extraction_status:"needs_review"});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_pages").get())
        .toMatchObject({n:0});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
        .toMatchObject({n:0});
      expect((await f.call(author,PREFIX+"/documents/"+uploaded.json.versionId+"/pages")).status).toBe(404);
      expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-19T12:20:00.000Z"))).selected).toBe(0);
      const backlog=await auditProcessingBacklog(f.db,{now:new Date("2026-11-19T12:20:00.000Z")});
      expect(backlog).toMatchObject({rejected:1,needsAttention:true,complete:true});
      expect(f.get).toHaveBeenCalledTimes(1);
    }finally{f.close();}
  });

  it("retries forged gateway signatures and mutated originals without admitting pages or leaking private details",async()=>{
    const f=await fixture();
    try{
      const author=await f.token("author");
      const created=await f.upload(author);
      await dispatchProcessingOutbox(f.db,f.queue,new Date(DATE));
      const message=f.queued.splice(0);
      f.setGatewayTransform(async response=>{
        if(!response.ok)return response;
        const data=await response.json() as {manifest:InspectedTextManifest;signature:string};
        return Response.json({...data,signature:"0".repeat(64)});
      });
      const tampered=await f.deliver(message);
      expect(tampered.result).toEqual({acked:0,retried:1,invalid:0});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_pages").get()).toMatchObject({n:0});
      expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions").get()).toMatchObject({extraction_status:"pending"});
      f.setGatewayTransform(async response=>response);

      const key=[...f.objects.keys()][0]!;
      const stored=f.objects.get(key);
      if(!stored)throw new Error("Synthetic R2 fixture disappeared");
      stored.bytes[10] = stored.bytes[10]! ^ 1;
      const corrupt=await f.deliver(message);
      expect(corrupt.result).toMatchObject({retried:1,acked:0});
      expect(f.forward).toHaveBeenCalledTimes(1); // hash mismatch stops before gateway
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get()).toMatchObject({n:0});
      const audit=await auditQuarantine(f.db,f.bucket,{now:new Date("2026-11-22T12:00:00.000Z")});
      expect(audit.integrityVerified).toBe(false); // metadata audit cannot certify bytes
      const pending=await f.call(author,PREFIX+"/documents/"+created.json.versionId+"/pages");
      expect(pending.status).toBe(404);
    }finally{f.close();}
  });

  it("pauses dispatch on a closed commission and rejects an already-queued job after closing",async()=>{
    const f=await fixture();
    try{
      const author=await f.token("author");
      await f.upload(author);
      f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
      const paused=await dispatchProcessingOutbox(f.db,f.queue,new Date(DATE));
      expect(paused).toEqual({selected:0,sent:0,failed:0});
      expect(f.forward).not.toHaveBeenCalled();
      f.sqlite.exec("UPDATE commissions SET status='active' WHERE id='c_a'");
      expect((await dispatchProcessingOutbox(f.db,f.queue,new Date(DATE))).sent).toBe(1);
      const queued=f.queued.splice(0);
      f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
      const stale=await f.deliver(queued);
      expect(stale.result).toEqual({acked:1,retried:0,invalid:0});
      expect(f.forward).not.toHaveBeenCalled();
      expect(f.get).not.toHaveBeenCalled();
      expect(f.sqlite.prepare("SELECT extraction_status FROM document_versions").get())
        .toMatchObject({extraction_status:"pending"});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
        .toMatchObject({n:0});
      const audit=await auditProcessingBacklog(f.db,{now:new Date("2026-11-19T12:20:00.000Z")});
      expect(audit).toMatchObject({paused:1,completed:0});
    }finally{f.close();}
  });

  it("caps outbox redelivery at ten attempts, reports exhaustion, and never deletes or invents a completed report",async()=>{
    const f=await fixture();
    try{
      const author=await f.token("author");
      await f.upload(author);
      for(let attempt=0;attempt<10;attempt++){
        const clock=new Date(new Date(DATE).getTime()+attempt*16*60_000);
        const result=await dispatchProcessingOutbox(f.db,f.queue,clock);
        expect(result).toMatchObject({selected:1,sent:1,failed:0});
        f.queued.length=0; // simulate lost messages / lack of an active consumer
      }
      expect((await dispatchProcessingOutbox(f.db,f.queue,new Date("2026-11-20T12:00:00.000Z"))).selected).toBe(0);
      expect(f.sqlite.prepare("SELECT state,attempts FROM document_processing_outbox").get())
        .toMatchObject({state:"sent",attempts:10});
      const report=await auditProcessingBacklog(f.db,{now:new Date("2026-11-20T12:00:00.000Z")});
      expect(report).toMatchObject({exhausted:1,needsAttention:true,completed:0});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get())
        .toMatchObject({n:0});
      expect(f.del).not.toHaveBeenCalled();
      expect(f.forward).not.toHaveBeenCalled();
    }finally{f.close();}
  });
});
