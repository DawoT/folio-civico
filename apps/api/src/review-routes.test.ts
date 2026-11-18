import { describe, expect, it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleReviewRequest } from "./review-routes";

function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('c_a','Comisión A','active'),('c_b','Comisión B','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('c_a','alice','member',1),('c_a','advisor','advisor',1),('c_a','observer','observer',1),('c_b','bob','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('b_a','c_a','Obras'),('b_b','c_b','Otro');
    INSERT INTO checklist_items(id,commission_id,area,expected_document)
      VALUES('item_a','c_a','works','Expediente de obra'),('item_b','c_b','procurement','Contrato');
  `);
  return f;
}
const base = "https://folio.test/api/commissions/c_a";
function post(body: unknown, headers: Record<string,string>={}) {
  return new Request(base+"/observations/drafts", {method:"POST",
    headers:{"Content-Type":"application/json","Idempotency-Key":"draft_req_12345",...headers},
    body:JSON.stringify(body)});
}

describe("human review endpoints", () => {
  it("lists checklist and observation drafts without unauthorised tenant leakage", async () => {
    const f=fixture();
    try {
      const checklist=await handleReviewRequest(new Request(base+"/checklist"),{DB:f.db},"alice","c_a","checklist");
      expect(checklist.status).toBe(200);
      expect(await checklist.json()).toMatchObject([{id:"item_a"}]);
      const other=await handleReviewRequest(new Request(base+"/checklist"),{DB:f.db},"bob","c_a","checklist");
      expect(other.status).toBe(404);
      const drafts=await handleReviewRequest(new Request(base+"/observations"),{DB:f.db},"alice","c_a","observations");
      expect(drafts.status).toBe(200);
      expect(await drafts.json()).toEqual([]);
    } finally {f.close();}
  });

  it("creates an unvalidated search-scope draft with server-issued reviewer and timestamp", async () => {
    const f=fixture();
    try {
      const request=post({title:"No ubicado",description:"No se encontró el expediente tras revisar el lote.",checklistItemId:"item_a",batchId:"b_a"});
      const result=await handleReviewRequest(request,{DB:f.db},"alice","c_a","drafts");
      expect(result.status).toBe(201);
      const value=await result.json() as {status:string; evidence:{reviewerId:string;searchedAt:string}[]};
      expect(value.status).toBe("draft");
      expect(value.evidence[0]?.reviewerId).toBe("alice");
      expect(value.evidence[0]?.searchedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      expect(result.headers.get("Cache-Control")).toBe("no-store");
    } finally {f.close();}
  });

  it("rejects browser CSRF, observers and wrong-commission evidence", async () => {
    const f=fixture();
    const body={title:"No ubicado",description:"Búsqueda manual realizada.",checklistItemId:"item_a",batchId:"b_a"};
    try {
      expect((await handleReviewRequest(post(body,{Origin:"https://attacker.test"}),{DB:f.db},"alice","c_a","drafts")).status).toBe(403);
      expect((await handleReviewRequest(post(body),{DB:f.db},"observer","c_a","drafts")).status).toBe(403);
      expect((await handleReviewRequest(post({...body,batchId:"b_b"}),{DB:f.db},"alice","c_a","drafts")).status).toBe(422);
      expect((await handleReviewRequest(post({...body,checklistItemId:"item_b"}),{DB:f.db},"alice","c_a","drafts")).status).toBe(422);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM observations").get()).toMatchObject({n:0});
    } finally {f.close();}
  });

  it("deduplicates retries and writes only one evidence and audit entry", async () => {
    const f=fixture();
    const input={title:"No ubicado",description:"Se revisó el expediente del lote.",checklistItemId:"item_a",batchId:"b_a"};
    try {
      const first=await handleReviewRequest(post(input),{DB:f.db},"alice","c_a","drafts");
      const second=await handleReviewRequest(post(input),{DB:f.db},"alice","c_a","drafts");
      expect(first.status).toBe(201);
      expect(second.status).toBe(200);
      const original=await first.json() as {id:string; evidence:unknown[]};
      const replay=await second.json() as {id:string; evidence:unknown[]};
      expect(replay).toMatchObject({id:original.id,evidence:original.evidence});
      for (const table of ["observations","observation_evidence","audit_events"]) {
        expect(f.sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get()).toMatchObject({n:1});
      }
    } finally {f.close();}
  });

  it("rejects conflicting payloads for the same key, including another checklist item", async () => {
    const f=fixture();
    const input={title:"No ubicado",description:"Búsqueda realizada",checklistItemId:"item_a",batchId:"b_a"};
    try {
      await handleReviewRequest(post(input),{DB:f.db},"alice","c_a","drafts");
      expect((await handleReviewRequest(post({...input,title:"Modificado"}),{DB:f.db},"alice","c_a","drafts")).status).toBe(409);
      expect((await handleReviewRequest(post({...input,checklistItemId:"item_b"}),{DB:f.db},"alice","c_a","drafts")).status).toBe(409);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM observations").get()).toMatchObject({n:1});
    } finally {f.close();}
  });

  it("scopes idempotency to the authenticated author", async () => {
    const f=fixture();
    const input={title:"No ubicado",description:"Búsqueda realizada",checklistItemId:"item_a",batchId:"b_a"};
    try {
      const first=await handleReviewRequest(post(input),{DB:f.db},"alice","c_a","drafts");
      const another=await handleReviewRequest(post(input),{DB:f.db},"advisor","c_a","drafts");
      expect(first.status).toBe(201);
      expect(another.status).toBe(201);
      expect((await first.json() as {id:string}).id).not.toBe((await another.json() as {id:string}).id);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM observations").get()).toMatchObject({n:2});
    } finally {f.close();}
  });

  it("deduplicates concurrent requests with a shared idempotency key", async () => {
    const f=fixture();
    const input={title:"No ubicado",description:"Búsqueda realizada",checklistItemId:"item_a",batchId:"b_a"};
    try {
      const [first,second]=await Promise.all([
        handleReviewRequest(post(input),{DB:f.db},"alice","c_a","drafts"),
        handleReviewRequest(post(input),{DB:f.db},"alice","c_a","drafts")
      ]);
      expect([first.status,second.status].sort()).toEqual([200,201]);
      expect((await first.json() as {id:string}).id).toBe((await second.json() as {id:string}).id);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM observations").get()).toMatchObject({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:1});
    } finally {f.close();}
  });

  it("requires a strong idempotency key for draft writes", async () => {
    const f=fixture();
    const input={title:"No ubicado",description:"Búsqueda realizada",checklistItemId:"item_a",batchId:"b_a"};
    try {
      expect((await handleReviewRequest(post(input,{"Idempotency-Key":"a"}),{DB:f.db},"alice","c_a","drafts")).status).toBe(400);
      expect((await handleReviewRequest(post(input,{"Idempotency-Key":""}),{DB:f.db},"alice","c_a","drafts")).status).toBe(400);
    } finally {f.close();}
  });

  it("refuses extra properties, oversized body, wrong content type and unsupported methods", async () => {
    const f=fixture();
    const body={title:"No ubicado",description:"Búsqueda manual realizada.",checklistItemId:"item_a",batchId:"b_a"};
    try {
      expect((await handleReviewRequest(post({...body, validatedBy:"alice"}),{DB:f.db},"alice","c_a","drafts")).status).toBe(400);
      expect((await handleReviewRequest(post({...body,description:"X".repeat(17000)}),{DB:f.db},"alice","c_a","drafts")).status).toBe(413);
      const wrong = new Request(base+"/observations/drafts",{method:"POST",headers:{"Content-Type":"text/plain","Idempotency-Key":"draft_req_67890"},body:"hello"});
      expect((await handleReviewRequest(wrong,{DB:f.db},"alice","c_a","drafts")).status).toBe(415);
      expect((await handleReviewRequest(new Request(base+"/checklist",{method:"DELETE"}),{DB:f.db},"alice","c_a","checklist")).status).toBe(405);
    } finally {f.close();}
  });
});
