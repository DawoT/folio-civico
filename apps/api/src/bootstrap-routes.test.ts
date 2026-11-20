import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {handleBootstrapRequest} from "./bootstrap-routes";

const endpoint="https://folio.test/api/commissions";
function request(body:unknown,key="bootstrap_api_key"){
  return new Request(endpoint,{
    method:"POST",
    headers:{"Content-Type":"application/json","Idempotency-Key":key},
    body:JSON.stringify(body)
  });
}
const body={name:"Comisión de Transferencia 2026",initialPresidentSubject:"lead"};
describe("operator-only initial commission bootstrap API",()=>{
  it("does not let an ordinary signed member replay a key already claimed by the trusted operator",async()=>{
    const f=makeD1();
    try{
      const privileged={DB:f.db,operatorSubject:"operator"};
      const created=await handleBootstrapRequest(request(body),privileged,"operator","create");
      expect(created.status).toBe(201);
      const id=(await created.json() as {id:string}).id;
      f.sqlite.prepare("UPDATE commissions SET status='closed' WHERE id=?").run(id);
      const replay=await handleBootstrapRequest(request(body),privileged,"operator","create");
      expect(replay.status).toBe(200); // Immutable operator journal receipt, not an active commission claim.
      expect(await replay.json()).toMatchObject({id,replayed:true});
      for(const caller of ["lead","outsider"]){
        const denied=await handleBootstrapRequest(request(body),privileged,caller,"create");
        expect(denied.status).toBe(403);
        expect(await denied.json()).toEqual({error:"Forbidden"});
      }
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:1});
    }finally{f.close();}
  });


  it("does not enable bootstrap without a configured trusted operator and signed subject",async()=>{
    const f=makeD1();
    try{
      expect((await handleBootstrapRequest(request(body),{DB:f.db},"operator","create")).status).toBe(403);
      expect((await handleBootstrapRequest(request(body),{
        DB:f.db,operatorSubject:"operator"
      },"outsider","create")).status).toBe(403);
      const capability=await handleBootstrapRequest(new Request(
        "https://folio.test/api/session"
      ),{DB:f.db,operatorSubject:"operator"},"outsider","capability");
      expect(capability.status).toBe(200);
      expect(await capability.json()).toEqual({subject:"outsider",canBootstrap:false});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commissions").get()).toMatchObject({n:0});
    }finally{f.close();}
  });
  it("authorized operator can create once, retry safely and initial president sees commission",async()=>{
    const f=makeD1();
    try{
      const env={DB:f.db,operatorSubject:"operator"};
      const capability=await handleBootstrapRequest(new Request(
        "https://folio.test/api/session"
      ),env,"operator","capability");
      expect(await capability.json()).toEqual({subject:"operator",canBootstrap:true});
      const created=await handleBootstrapRequest(request(body),env,"operator","create");
      expect(created.status).toBe(201);
      expect(created.headers.get("Cache-Control")).toBe("no-store");
      const record=await created.json() as {id:string;replayed:boolean};
      expect(record.replayed).toBe(false);
      const retried=await handleBootstrapRequest(request(body),env,"operator","create");
      expect(retried.status).toBe(200);
      expect(await retried.json()).toMatchObject({...record,replayed:true});
      const collision=await handleBootstrapRequest(request({...body,name:"Otra Comisión"}),env,"operator","create");
      expect(collision.status).toBe(409);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:1});
    }finally{f.close();}
  });
  it("blocks arbitrary creator fields, foreign origins and unsupported verbs",async()=>{
    const f=makeD1();
    try{
      const env={DB:f.db,operatorSubject:"operator"};
      const extra=await handleBootstrapRequest(request({...body,createdBy:"operator"}),env,"operator","create");
      expect(extra.status).toBe(400);
      const foreign=new Request(endpoint,{
        method:"POST",headers:{"Content-Type":"application/json","Idempotency-Key":"bootstrap_test_123",
          "Origin":"https://not-folio.example"},body:JSON.stringify(body)
      });
      expect((await handleBootstrapRequest(foreign,env,"operator","create")).status).toBe(403);
      const wrongMethod=await handleBootstrapRequest(new Request(endpoint,{method:"DELETE"}),env,"operator","create");
      expect(wrongMethod.status).toBe(405);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commissions").get()).toMatchObject({n:0});
    }finally{f.close();}
  });
});
