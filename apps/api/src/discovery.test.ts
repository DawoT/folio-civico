import { beforeEach, describe, expect, it, vi } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleApiRequest } from "./index";
import { authenticateAccess } from "@folio/auth";

vi.mock("@folio/auth", () => ({ authenticateAccess: vi.fn() }));
const mockAuth = vi.mocked(authenticateAccess);

/** Reuse actual D1/SQLite rows, then interleave a membership change before discovery responds. */
function afterDiscoveryRows(db:D1Database, afterFirst:()=>void, failSecond=false):D1Database {
  let reads=0;
  return {
    prepare(sql:string){
      const prepared=db.prepare(sql);
      if(!sql.includes("ORDER BY CASE c.status WHEN 'active' THEN 0 ELSE 1 END")) return prepared;
      return {
        bind(...params:unknown[]){
          const bound=prepared.bind(...params);
          return {
            async all<T>(){
              reads++;
              if(reads===2 && failSecond) throw new Error("PRIVATE_D1_DISCOVERY_FENCE_FAILURE");
              const rows=await bound.all<T>();
              if(reads===1) afterFirst();
              return rows;
            }
          };
        }
      } as unknown as D1PreparedStatement;
    }
  } as D1Database;
}

describe("API authenticated discovery", () => {
  beforeEach(() => mockAuth.mockReset());

  function fixture() {
    const f = makeD1();
    f.sqlite.exec(`
      INSERT INTO commissions(id,name) VALUES ('c_a','Comisión A'),('c_b','Comisión B');
      INSERT INTO commission_members(commission_id,subject,role,active)
        VALUES ('c_a','alice','member',1),('c_b','bob','member',1);
      INSERT INTO document_batches(id,commission_id,label)
        VALUES ('ba_1','c_a','Obras'),('bb_1','c_b','Contrataciones');
    `);
    return f;
  }

  it("does not expose commission discovery without identity", async () => {
    mockAuth.mockResolvedValue(null);
    const f=fixture();
    try {
      const response=await handleApiRequest(new Request("https://folio.test/api/commissions"),{ DB:f.db });
      expect(response.status).toBe(401);
    } finally {f.close();}
  });

  it("returns only commissions and batches assigned to the signed-in subject", async () => {
    mockAuth.mockResolvedValue("alice");
    const f=fixture();
    try {
      const env={DB:f.db};
      const commissions=await handleApiRequest(new Request("https://folio.test/api/commissions"),env);
      expect(commissions.status).toBe(200);
      expect(await commissions.json()).toMatchObject([{id:"c_a"}]);
      const batches=await handleApiRequest(new Request("https://folio.test/api/commissions/c_a/batches"),env);
      expect(batches.status).toBe(200);
      expect(await batches.json()).toEqual([{id:"ba_1",label:"Obras"}]);
      const blocked=await handleApiRequest(new Request("https://folio.test/api/commissions/c_b/batches"),env);
      expect(blocked.status).toBe(404);
      expect(blocked.headers.get("Cache-Control")).toBe("no-store");
    } finally {f.close();}
  });

  it("does not disclose a revoked commission after a discovery read, while retaining other authorized commissions",async()=>{
    mockAuth.mockResolvedValue("alice");
    const f=fixture();
    try {
      f.sqlite.exec("INSERT INTO commission_members(commission_id,subject,role,active) VALUES('c_b','alice','advisor',1)");
      const raced=afterDiscoveryRows(f.db,()=>{
        f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
      });
      const response=await handleApiRequest(new Request("https://folio.test/api/commissions"),{DB:raced});
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual([{id:"c_b",name:"Comisión B",status:"active",role:"advisor"}]);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
    } finally {f.close();}
  });

  it("does not disclose any commission after the subject loses the only membership",async()=>{
    mockAuth.mockResolvedValue("alice");
    const f=fixture();
    try {
      const raced=afterDiscoveryRows(f.db,()=>{
        f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
      });
      const response=await handleApiRequest(new Request("https://folio.test/api/commissions"),{DB:raced});
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual([]);
    } finally {f.close();}
  });

  it("returns the current role rather than an obsolete capability after discovery",async()=>{
    mockAuth.mockResolvedValue("alice");
    const f=fixture();
    try {
      const raced=afterDiscoveryRows(f.db,()=>{
        f.sqlite.exec("UPDATE commission_members SET role='observer' WHERE commission_id='c_a' AND subject='alice'");
      });
      const response=await handleApiRequest(new Request("https://folio.test/api/commissions"),{DB:raced});
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject([{id:"c_a",role:"observer"}]);
    } finally {f.close();}
  });

  it("fails closed if the final discovery authority read cannot complete",async()=>{
    mockAuth.mockResolvedValue("alice");
    const f=fixture();
    try {
      const raced=afterDiscoveryRows(f.db,()=>{},true);
      const response=await handleApiRequest(new Request("https://folio.test/api/commissions"),{DB:raced});
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({error:"Request could not be completed"});
      expect(response.headers.get("Cache-Control")).toBe("no-store");
    } finally {f.close();}
  });

  it("does not reveal batches if membership is revoked after their D1 query",async()=>{
    mockAuth.mockResolvedValue("alice");
    const f=fixture();
    try{
      let triggered=false;
      const raced={
        prepare(sql:string){
          const statement=f.db.prepare(sql);
          if(!sql.includes("SELECT b.id, b.label")) return statement;
          return {
            bind(...params:unknown[]){
              const bound=statement.bind(...params);
              return {
                async all<T>(){
                  const result=await bound.all<T>();
                  triggered=true;
                  f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
                  return result;
                }
              };
            }
          } as unknown as D1PreparedStatement;
        }
      } as D1Database;
      const res=await handleApiRequest(new Request("https://folio.test/api/commissions/c_a/batches"),{DB:raced});
      expect(triggered).toBe(true);
      expect(res.status).toBe(404);
      expect(await res.json()).toEqual({error:"Not found"});
      expect(res.headers.get("Cache-Control")).toBe("no-store");
    }finally{f.close();}
  });

  it("denies bootstrap to ordinary signed members and rejects malformed discovery routes", async () => {
    mockAuth.mockResolvedValue("alice");
    const f=fixture();
    try {
      const post=await handleApiRequest(new Request("https://folio.test/api/commissions",{method:"POST"}),{DB:f.db});
      expect(post.status).toBe(403); // No trusted operator binding: fail closed.
      const malformed=await handleApiRequest(new Request("https://folio.test/api/commissions/../batches"),{DB:f.db});
      expect(malformed.status).toBe(404);
    } finally {f.close();}
  });
});
