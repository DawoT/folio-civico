import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {handleReviewableCountRequest} from "./reviewable-count-routes";

function fixture(){
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('a','Synthetic A','active'),('b','Synthetic B','active');
    INSERT INTO commission_members(commission_id,subject,role,active)
    VALUES('a','author','member',1),('a','reviewer','member',1),
      ('a','observer','observer',1),('a','advisor','advisor',1),
      ('a','revoked','member',0),('b','outside','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('batch','a','Synthetic');
    INSERT INTO checklist_items(id,commission_id,area,expected_document)
      VALUES('item','a','works','Synthetic');
    INSERT INTO observations(id,commission_id,author_subject,title,description)
      VALUES('other_review','a','author','Synthetic review','Evidence'),
        ('own_draft','a','reviewer','Own draft','Evidence');
    INSERT INTO observation_evidence(id,observation_id,type,reference_json)
      VALUES('e','other_review','SEARCH_SCOPE',
        '{"type":"SEARCH_SCOPE","commissionId":"a","checklistItemId":"item","batchId":"batch","reviewerId":"author","searchedAt":"2026-11-20T12:00:00.000Z"}');
    UPDATE observations SET status='in_review',submitted_by='author',
      submitted_at=CURRENT_TIMESTAMP,submit_request_key='submit_review_001'
      WHERE id='other_review';
  `);
  return f;
}
const base="https://folio.test/api/commissions/a/observations/reviewable-count";
const request=(query="")=>new Request(base+query);

function afterCount(db:D1Database,change:()=>void):D1Database{
  let once=false;
  return {
    prepare(sql:string){
      const stmt=db.prepare(sql);
      if(!sql.includes("SELECT COUNT(*) AS count")) return stmt;
      return {
        bind(...args:unknown[]){
          const bound=stmt.bind(...args);
          return {
            async first<T>(){
              const result=await bound.first<T>();
              if(!once){once=true;change();}
              return result;
            }
          };
        }
      } as unknown as D1PreparedStatement;
    }
  } as D1Database;
}

describe("complete authorized reviewable count API",()=>{
  it("returns exactly the complete subject-scoped total with no-store, and no audit mutations",async()=>{
    const f=fixture();
    try {
      const before=f.sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get();
      const response=await handleReviewableCountRequest(request(),{DB:f.db},"reviewer","a");
      expect(response.status).toBe(200);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(await response.json()).toEqual({commissionId:"a",count:1});
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get()).toEqual(before);
    }finally{f.close();}
  });

  it("distinguishes legitimate empty queues from missing commission membership",async()=>{
    const f=fixture();
    try{
      for(const subject of ["author","observer","advisor"]) {
        const response=await handleReviewableCountRequest(request(),{DB:f.db},subject,"a");
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({commissionId:"a",count:0});
      }
      f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='a'");
      const closed=await handleReviewableCountRequest(request(),{DB:f.db},"reviewer","a");
      expect(closed.status).toBe(200);
      expect(await closed.json()).toEqual({commissionId:"a",count:0});
      for(const subject of ["revoked","outside","missing"]) {
        const denied=await handleReviewableCountRequest(request(),{DB:f.db},subject,"a");
        expect(denied.status).toBe(404);
        expect(await denied.json()).toEqual({error:"Not found"});
      }
    }finally{f.close();}
  });

  it("does not acknowledge an empty queue after membership revocation during the first authorization read",async()=>{
    const f=fixture();
    try{
      let changed=false;
      const db={
        prepare(sql:string){
          const stmt=f.db.prepare(sql);
          if(!sql.includes("SELECT c.id, c.name, c.status, m.role")) return stmt;
          return {
            bind(...args:unknown[]){
              const bound=stmt.bind(...args);
              return {async first<T>(){
                const result=await bound.first<T>();
                if(!changed){
                  changed=true;
                  f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='a' AND subject='observer'");
                }
                return result;
              }};
            }
          } as unknown as D1PreparedStatement;
        }
      } as D1Database;
      const response=await handleReviewableCountRequest(request(),{DB:db},"observer","a");
      expect(changed).toBe(true);
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual({error:"Not found"});
      expect(response.headers.get("Cache-Control")).toBe("no-store");
    }finally{f.close();}
  });

  it("rejects unsupported methods and query filters before querying D1",async()=>{
    const f=fixture();
    try{
      const method=await handleReviewableCountRequest(
        new Request(base,{method:"POST"}),{DB:f.db},"reviewer","a");
      expect(method.status).toBe(405);
      const filters=await handleReviewableCountRequest(
        request("?status=in_review"),{DB:f.db},"reviewer","a");
      expect(filters.status).toBe(400);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:1});
    }finally{f.close();}
  });

  it.each(["revoked","observer","advisor","closed"] as const)(
    "fences an already fetched count when authority becomes %s during the query",async(change)=>{
      const f=fixture();
      try {
        let raced=false;
        const db=afterCount(f.db,()=>{
          raced=true;
          if(change==="closed")f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='a'");
          else if(change==="revoked")f.sqlite.exec(
            "UPDATE commission_members SET active=0 WHERE commission_id='a' AND subject='reviewer'");
          else f.sqlite.prepare(
            "UPDATE commission_members SET role=? WHERE commission_id='a' AND subject='reviewer'"
          ).run(change);
        });
        const response=await handleReviewableCountRequest(request(),{DB:db},"reviewer","a");
        expect(raced).toBe(true);
        expect(response.status).toBe(change==="revoked"?404:200);
        expect(await response.json()).toEqual(change==="revoked"
          ? {error:"Not found"}:{commissionId:"a",count:0});
        expect(response.headers.get("Cache-Control")).toBe("no-store");
      }finally{f.close();}
    }
  );

  it("fails with 503 and no count when D1 fails during the final authorization check",async()=>{
    const f=fixture();
    try{
      let counted=false;
      const db={
        prepare(sql:string){
          if(counted && sql.includes("SELECT c.id, c.name, c.status, m.role")) {
            throw new Error("PRIVATE_D1_FINAL_AUTHORIZATION_ERROR");
          }
          const stmt=f.db.prepare(sql);
          if(!sql.includes("SELECT COUNT(*) AS count")) return stmt;
          return {
            bind(...args:unknown[]){
              const bound=stmt.bind(...args);
              return {async first<T>(){
                const result=await bound.first<T>();
                counted=true;
                return result;
              }};
            }
          } as unknown as D1PreparedStatement;
        }
      } as D1Database;
      const response=await handleReviewableCountRequest(request(),{DB:db},"reviewer","a");
      expect(counted).toBe(true);
      expect(response.status).toBe(503);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(await response.json()).toEqual({error:"Request could not be completed"});
    }finally{f.close();}
  });
});
