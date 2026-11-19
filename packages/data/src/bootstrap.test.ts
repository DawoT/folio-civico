import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {createPilotCommission,CommissionBootstrapConflictError,
  CommissionBootstrapInputError} from "./bootstrap";
import {listAccessibleCommissions} from "./commissions";

const request={operatorSubject:"operator",initialPresidentSubject:"lead",
  name:"Comisión de Transferencia Obras 2026",requestKey:"bootstrap_req_12345"};

describe("operator-scoped initial pilot commission bootstrap",()=>{
  it("creates a commission and initial president in one audit transaction",async()=>{
    const f=makeD1();
    try {
      const result=await createPilotCommission(f.db,request);
      expect(result).toMatchObject({name:request.name,initialPresidentSubject:"lead",replayed:false});
      expect(result.id).toMatch(/^[a-z0-9-]{1,64}$/);
      expect(await listAccessibleCommissions(f.db,"lead")).toEqual(expect.arrayContaining([
        expect.objectContaining({id:result.id,name:request.name,role:"president",status:"active"})
      ]));
      expect(f.sqlite.prepare("SELECT action,actor_subject AS actor,resource_id AS resource FROM audit_events").get())
        .toMatchObject({action:"commission.created",actor:"operator",resource:result.id});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commission_members").get()).toMatchObject({n:1});
    }finally{f.close();}
  });
  it("retries with same key without creating duplicates and refuses different payloads",async()=>{
    const f=makeD1();
    try {
      const original=await createPilotCommission(f.db,request);
      const replay=await createPilotCommission(f.db,{...request,name:"  Comisión de Transferencia Obras 2026  "});
      expect(replay).toMatchObject({id:original.id,replayed:true});
      await expect(createPilotCommission(f.db,{...request,name:"Otra comisión"}))
        .rejects.toBeInstanceOf(CommissionBootstrapConflictError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commissions").get()).toMatchObject({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:1});
    }finally{f.close();}
  });
  it("rejects invalid identities, control characters and limits commissions per initial president",async()=>{
    const f=makeD1();
    try {
      await expect(createPilotCommission(f.db,{...request,operatorSubject:"operator\n"}))
        .rejects.toBeInstanceOf(CommissionBootstrapInputError);
      await expect(createPilotCommission(f.db,{...request,initialPresidentSubject:"  "}))
        .rejects.toBeInstanceOf(CommissionBootstrapInputError);
      for(let i=0;i<50;i++){
        f.sqlite.prepare("INSERT INTO commissions(id,name) VALUES (?,?)").run("c_"+i,"Comisión "+i);
        f.sqlite.prepare("INSERT INTO commission_members(commission_id,subject,role) VALUES (?,'lead','president')").run("c_"+i);
      }
      await expect(createPilotCommission(f.db,request))
        .rejects.toBeInstanceOf(CommissionBootstrapConflictError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:0});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commission_bootstrap_requests").get()).toMatchObject({n:0});
    }finally{f.close();}
  });
  it("bootstrap journal is immutable",async()=>{
    const f=makeD1();
    try{
      await createPilotCommission(f.db,request);
      expect(()=>f.sqlite.exec("DELETE FROM commission_bootstrap_requests")).toThrow(/BOOTSTRAP_IMMUTABLE/);
      expect(()=>f.sqlite.exec("UPDATE commission_bootstrap_requests SET name='Other'")).toThrow(/BOOTSTRAP_IMMUTABLE/);
    }finally{f.close();}
  });
});
