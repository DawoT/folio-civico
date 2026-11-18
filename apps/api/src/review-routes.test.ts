import { describe, expect, it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleReviewRequest } from "./review-routes";

function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('c_a','Comisión A','active'),('c_b','Comisión B','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('c_a','alice','member',1),('c_a','observer','observer',1),('c_b','bob','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('b_a','c_a','Obras'),('b_b','c_b','Otro');
    INSERT INTO checklist_items(id,commission_id,area,expected_document)
      VALUES('item_a','c_a','works','Expediente de obra'),('item_b','c_b','procurement','Contrato');
  `);
  return f;
}
const base = "https://folio.test/api/commissions/c_a";
function post(body: unknown, headers: Record<string,string>={}) {
  return new Request(base+"/observations/drafts", {method:"POST",
    headers:{"Content-Type":"application/json",...headers},
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

  it("refuses extra properties, oversized body, wrong content type and unsupported methods", async () => {
    const f=fixture();
    const body={title:"No ubicado",description:"Búsqueda manual realizada.",checklistItemId:"item_a",batchId:"b_a"};
    try {
      expect((await handleReviewRequest(post({...body, validatedBy:"alice"}),{DB:f.db},"alice","c_a","drafts")).status).toBe(400);
      expect((await handleReviewRequest(post({...body,description:"X".repeat(17000)}),{DB:f.db},"alice","c_a","drafts")).status).toBe(413);
      const wrong = new Request(base+"/observations/drafts",{method:"POST",headers:{"Content-Type":"text/plain"},body:"hello"});
      expect((await handleReviewRequest(wrong,{DB:f.db},"alice","c_a","drafts")).status).toBe(415);
      expect((await handleReviewRequest(new Request(base+"/checklist",{method:"DELETE"}),{DB:f.db},"alice","c_a","checklist")).status).toBe(405);
    } finally {f.close();}
  });
});
