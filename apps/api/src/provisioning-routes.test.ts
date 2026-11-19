import { describe,expect,it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleProvisioningRequest } from "./provisioning-routes";

function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('a','Comisión A','active'),('b','B','active'),('closed','Cerrada','closed');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('a','president','president',1),('a','reader','observer',1),
      ('a','advisor','advisor',1),('a','revoked','president',0),
      ('b','other','president',1),('closed','president','president',1);
  `);
  return f;
}
function request(kind:"batch"|"checklist",body:unknown,key="provision_req_12345",origin?:string) {
  return new Request("https://folio.test/api/commissions/a/"+(kind==="batch"?"batches":"checklist/items"),{
    method:"POST",
    headers:{"Content-Type":"application/json","Idempotency-Key":key,
      ...(origin?{Origin:origin}:{})},
    body:JSON.stringify(body)
  });
}

describe("commission president provisioning API",()=>{
  it("creates and replays a batch and a checklist item using independent keys",async()=>{
    const f=fixture();
    try {
      const body={label:"Obras 2026"};
      const first=await handleProvisioningRequest(request("batch",body),{DB:f.db},"president","a","batch");
      expect(first.status).toBe(201);
      expect(first.headers.get("Cache-Control")).toBe("no-store");
      const created=await first.json() as {id:string;replayed:boolean};
      expect(created.replayed).toBe(false);
      const second=await handleProvisioningRequest(request("batch",body),{DB:f.db},"president","a","batch");
      expect(second.status).toBe(200);
      expect(await second.json()).toMatchObject({id:created.id,replayed:true});
      const checklist=await handleProvisioningRequest(request("checklist",{
        area:"procurement",expectedDocument:"Contrato base"
      },"checklist_key_12345"),{DB:f.db},"president","a","checklist");
      expect(checklist.status).toBe(201);
      expect(await checklist.json()).toMatchObject({status:"pending",area:"procurement"});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:2});
    } finally {f.close();}
  });

  it("forbids other roles, foreign origins, closed commissions and cross-commission identities",async()=>{
    const f=fixture();
    try {
      for(const subject of ["reader","advisor"]){
        expect((await handleProvisioningRequest(request("batch",{label:"Obras"}),{DB:f.db},subject,"a","batch")).status).toBe(403);
      }
      for(const subject of ["revoked","other","unknown"]){
        expect((await handleProvisioningRequest(request("batch",{label:"Obras"}),{DB:f.db},subject,"a","batch")).status).toBe(404);
      }
      expect((await handleProvisioningRequest(request("batch",{label:"Obras"}),{DB:f.db},"president","closed","batch")).status).toBe(409);
      expect((await handleProvisioningRequest(request("batch",{label:"Obras"},undefined,"https://evil.test"),{DB:f.db},"president","a","batch")).status).toBe(403);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_batches").get()).toMatchObject({n:0});
    } finally {f.close();}
  });

  it("rejects malformed payloads, unknown fields, oversized body, missing key and cross-kind key reuse",async()=>{
    const f=fixture();
    try {
      expect((await handleProvisioningRequest(request("batch",{label:"Obras",actor:"other"}),{DB:f.db},"president","a","batch")).status).toBe(400);
      expect((await handleProvisioningRequest(request("checklist",{area:"works"}),{DB:f.db},"president","a","checklist")).status).toBe(400);
      expect((await handleProvisioningRequest(request("batch",{label:"x".repeat(5000)}),{DB:f.db},"president","a","batch")).status).toBe(413);
      expect((await handleProvisioningRequest(request("batch",{label:"Obras"},"tiny"),{DB:f.db},"president","a","batch")).status).toBe(400);
      expect((await handleProvisioningRequest(new Request("https://folio.test/api/commissions/a/batches",{
        method:"GET"
      }),{DB:f.db},"president","a","batch")).status).toBe(405);
      expect((await handleProvisioningRequest(request("batch",{label:"Obras"}),{DB:f.db},"president","a","batch")).status).toBe(201);
      expect((await handleProvisioningRequest(request("checklist",{area:"works",expectedDocument:"Obras"}),{DB:f.db},"president","a","checklist")).status).toBe(409);
    } finally {f.close();}
  });
});
