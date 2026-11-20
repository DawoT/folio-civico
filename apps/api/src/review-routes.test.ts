import { describe, expect, it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleReviewRequest } from "./review-routes";
import { afterEvidenceRead } from "../../../tests/helpers/d1-revocation-race";

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

function afterReviewList(
  db:D1Database, marker:string, revoke:()=>void
):D1Database {
  let fired=false;
  return {
    prepare(sql:string){
      const prepared=db.prepare(sql);
      if(!sql.includes(marker)) return prepared;
      return {
        bind(...params:unknown[]) {
          const statement=prepared.bind(...params);
          return {
            async all<T>() {
              const result=await statement.all<T>();
              if(!fired){fired=true;revoke();}
              return result;
            }
          };
        }
      } as unknown as D1PreparedStatement;
    }
  } as D1Database;
}

describe("human review endpoints", () => {
  it.each([
    ["checklist","FROM checklist_items i","checklist"],
    ["observations","FROM (SELECT id FROM observations","observations"],
    ["history","WITH chosen AS (","observations/history"]
  ] as const)(
    "fails closed when membership is revoked after the %s query returns",
    async(action,marker,route) => {
      const f=fixture();
      try {
        const before=f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get();
        const raced=afterReviewList(f.db,marker,()=>{
          f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
        });
        const response=await handleReviewRequest(new Request(base+"/"+route),{DB:raced},"alice","c_a",action);
        expect(response.status).toBe(404);
        expect(await response.json()).toEqual({error:"Not found"});
        expect(response.headers.get("Cache-Control")).toBe("no-store");
        expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual(before);
      }finally{f.close();}
    }
  );

  it("retains checklist and history read access for members of closed commissions",async()=>{
    const f=fixture();
    try{
      f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
      for(const [action,route] of [["checklist","checklist"],["observations","observations"],["history","observations/history"]] as const){
        const response=await handleReviewRequest(new Request(base+"/"+route),{DB:f.db},"alice","c_a",action);
        expect(response.status).toBe(200);
      }
    }finally{f.close();}
  });


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

  it.each(["revoked","closed","observer"] as const)(
    "does not acknowledge a committed draft when access becomes %s during D1.batch",
    async(change)=>{
      const f=fixture();
      const input={title:"Búsqueda documentada",description:"Se revisó el lote sin localizar la documentación",
        checklistItemId:"item_a",batchId:"b_a"};
      try{
        let committed=false;
        const raced={
          prepare:f.db.prepare.bind(f.db),
          async batch(statements:D1PreparedStatement[]){
            const results=await f.db.batch(statements);
            committed=true;
            if(change==="revoked"){
              f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
            }else if(change==="closed"){
              f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
            }else{
              f.sqlite.exec("UPDATE commission_members SET role='observer' WHERE commission_id='c_a' AND subject='alice'");
            }
            return results;
          }
        } as D1Database;
        const result=await handleReviewRequest(post(input),{DB:raced},"alice","c_a","drafts");
        expect(committed).toBe(true);
        expect(result.status).toBe(403);
        expect(await result.json()).toEqual({error:"Forbidden"});
        expect(result.headers.get("Cache-Control")).toBe("no-store");
        for(const table of ["observations","observation_evidence","audit_events"]){
          expect(f.sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get()).toEqual({n:1});
        }
      }finally{f.close();}
    }
  );

  it("does not announce a committed draft after the final D1 authorization query fails",async()=>{
    const f=fixture();
    try{
      let committed=false;
      const raced={
        prepare(sql:string){
          if(committed && sql.includes("SELECT c.id, c.name, c.status, m.role")){
            throw new Error("PRIVATE_D1_AFTER_DRAFT_COMMIT");
          }
          return f.db.prepare(sql);
        },
        async batch(statements:D1PreparedStatement[]){
          const results=await f.db.batch(statements);
          committed=true;
          return results;
        }
      } as D1Database;
      const result=await handleReviewRequest(post({title:"No ubicado",description:"Búsqueda documentada",
        checklistItemId:"item_a",batchId:"b_a"}),{DB:raced},"alice","c_a","drafts");
      expect(committed).toBe(true);
      expect(result.status).toBe(503);
      expect(await result.json()).toEqual({error:"Request could not be completed"});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM observations").get()).toEqual({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:1});
    }finally{f.close();}
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

  it.each(["revoked","closed","downgraded"] as const)(
    "never replays a successful idempotent draft after commission access becomes %s during evidence read",
    async (change) => {
      const f=fixture();
      const body={title:"No ubicado",description:"Búsqueda realizada",checklistItemId:"item_a",batchId:"b_a"};
      try {
        const original=await handleReviewRequest(post(body),{DB:f.db},"alice","c_a","drafts");
        expect(original.status).toBe(201);
        const before=f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get();
        const raced=afterEvidenceRead(f.db, () => {
          if (change==="revoked") {
            f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
          } else if (change==="closed") {
            f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
          } else {
            f.sqlite.exec("UPDATE commission_members SET role='observer' WHERE commission_id='c_a' AND subject='alice'");
          }
        });
        const replay=await handleReviewRequest(post(body),{DB:raced},"alice","c_a","drafts");
        expect(replay.status).toBe(403);
        expect(await replay.json()).toEqual({error:"Forbidden"});
        expect(f.sqlite.prepare("SELECT count(*) AS n FROM observations").get()).toEqual({n:1});
        expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual(before);
      } finally {f.close();}
    }
  );

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
