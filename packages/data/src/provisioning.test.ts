import { describe,expect,it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import {afterFirstRead,aroundBatch} from "../../../tests/helpers/d1-write-replay-race";
import {
  createCommissionBatch, createCommissionChecklistItem,
  ProvisioningAccessError, ProvisioningConflictError
} from "./provisioning";
import { listChecklist } from "./review";
import { listCommissionBatches } from "./commissions";

function fixture(){
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('a','A','active'),('b','B','active'),('closed','Closed','closed');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('a','president','president',1),('a','member','member',1),
      ('a','observer','observer',1),('a','revoked','president',0),
      ('b','other','president',1),('closed','president','president',1);
  `);
  return f;
}
const batchInput={commissionId:"a",subject:"president",label:"Obras 2026",requestKey:"batch_req_12345"};
const itemInput={commissionId:"a",subject:"president",area:"works" as const,
  expectedDocument:"Expediente de obra",requestKey:"checklist_req_12345"};

describe("president-only idempotent commission provisioning",()=>{
  it.each(["revoked","demoted","closed"] as const)(
    "never replays a batch after the president becomes %s during the resource read",
    async(change)=>{
      const f=fixture();
      try{
        await createCommissionBatch(f.db,batchInput);
        const raced=afterFirstRead(f.db,"SELECT id,label FROM document_batches",()=>{
          if(change==="revoked") {
            f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='a' AND subject='president'");
          } else if(change==="demoted") {
            f.sqlite.exec("UPDATE commission_members SET role='member' WHERE commission_id='a' AND subject='president'");
          } else {
            f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='a'");
          }
        });
        await expect(createCommissionBatch(raced,batchInput)).rejects.toBeInstanceOf(
          change==="closed"?ProvisioningConflictError:ProvisioningAccessError
        );
        expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_batches").get()).toEqual({n:1});
        expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:1});
      }finally{f.close();}
    }
  );

  it("never replays a checklist item if presidency is revoked during its resource read",async()=>{
    const f=fixture();
    try{
      await createCommissionChecklistItem(f.db,itemInput);
      const raced=afterFirstRead(f.db,"FROM checklist_items WHERE id=?",()=>{
        f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='a' AND subject='president'");
      });
      await expect(createCommissionChecklistItem(raced,itemInput)).rejects.toBeInstanceOf(ProvisioningAccessError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM checklist_items").get()).toEqual({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:1});
    }finally{f.close();}
  });

  it("never replays the winner after a competing provisioning transaction invalidates presidency",async()=>{
    const f=fixture();
    try{
      const raced=aroundBatch(f.db,async()=>{
        await createCommissionBatch(f.db,batchInput);
        f.sqlite.exec("UPDATE commission_members SET role='observer' WHERE commission_id='a' AND subject='president'");
        throw new Error("SYNTHETIC_CONCURRENT_PROVISION_KEY");
      });
      await expect(createCommissionBatch(raced,batchInput)).rejects.toBeInstanceOf(ProvisioningAccessError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commission_provisioning_requests").get()).toEqual({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:1});
    }finally{f.close();}
  });

  it("does not acknowledge a just-committed checklist write after commission closure during D1.batch",async()=>{
    const f=fixture();
    try{
      const raced=aroundBatch(f.db,async statements=>{
        const results=await f.db.batch(statements);
        f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='a'");
        return results;
      });
      await expect(createCommissionChecklistItem(raced,itemInput)).rejects.toBeInstanceOf(ProvisioningConflictError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM checklist_items").get()).toEqual({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:1});
    }finally{f.close();}
  });


  it("creates a batch, a pending checklist item and two audit events atomically",async()=>{
    const f=fixture();
    try{
      const batch=await createCommissionBatch(f.db,batchInput);
      const item=await createCommissionChecklistItem(f.db,itemInput);
      expect(batch).toMatchObject({label:"Obras 2026",replayed:false});
      expect(item).toMatchObject({area:"works",status:"pending",replayed:false});
      expect(await listCommissionBatches(f.db,"member","a")).toMatchObject([{id:batch.id}]);
      expect(await listChecklist(f.db,"member","a")).toMatchObject([{id:item.id,status:"pending"}]);
      const events=f.sqlite.prepare("SELECT action,actor_subject AS actor FROM audit_events ORDER BY created_at,id").all();
      expect(events).toHaveLength(2);
      expect(events.map((e)=>e.action).sort()).toEqual(["commission.batch_created","commission.checklist_item_created"]);
      expect(events.every(e=>e.actor==="president")).toBe(true);
    }finally{f.close();}
  });

  it("replays the same request without duplicating resources or audit; conflicts on different bodies and operations",async()=>{
    const f=fixture();
    try{
      const batch=await createCommissionBatch(f.db,batchInput);
      const replay=await createCommissionBatch(f.db,{...batchInput,label:"  Obras 2026  "});
      expect(replay).toMatchObject({id:batch.id,replayed:true});
      await expect(createCommissionBatch(f.db,{...batchInput,label:"Otro lote"}))
        .rejects.toBeInstanceOf(ProvisioningConflictError);
      await expect(createCommissionChecklistItem(f.db,{...itemInput,requestKey:batchInput.requestKey}))
        .rejects.toBeInstanceOf(ProvisioningConflictError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_batches").get()).toMatchObject({n:1});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:1});
    }finally{f.close();}
  });

  it("denies non-president, revoked, foreign and closed commission actions",async()=>{
    const f=fixture();
    try{
      for(const subject of ["member","observer","revoked","other","unknown"]){
        await expect(createCommissionBatch(f.db,{...batchInput,subject}))
          .rejects.toBeInstanceOf(ProvisioningAccessError);
        await expect(createCommissionChecklistItem(f.db,{...itemInput,subject}))
          .rejects.toBeInstanceOf(ProvisioningAccessError);
      }
      await expect(createCommissionBatch(f.db,{...batchInput,commissionId:"closed"}))
        .rejects.toBeInstanceOf(ProvisioningConflictError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:0});
    }finally{f.close();}
  });

  it("rejects malformed inputs and limits provisioning without silently hiding entries",async()=>{
    const f=fixture();
    try{
      await expect(createCommissionBatch(f.db,{...batchInput,label:"\nBad"})).rejects.toThrow();
      await expect(createCommissionChecklistItem(f.db,{...itemInput,expectedDocument:" "}))
        .rejects.toThrow();
      await expect(createCommissionBatch(f.db,{...batchInput,requestKey:"tiny"})).rejects.toThrow();
      for(let i=0;i<100;i++){
        f.sqlite.prepare("INSERT INTO document_batches(id,commission_id,label) VALUES(?,?,?)")
          .run("seed"+i,"a","Batch "+i);
      }
      await expect(createCommissionBatch(f.db,batchInput))
        .rejects.toBeInstanceOf(ProvisioningConflictError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM commission_provisioning_requests").get()).toMatchObject({n:0});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:0});
    }finally{f.close();}
  });

  it("rejects modifying or deleting a saved provisioning request",async()=>{
    const f=fixture();
    try{
      await createCommissionBatch(f.db,batchInput);
      expect(()=>f.sqlite.exec("UPDATE commission_provisioning_requests SET operation='checklist'"))
        .toThrow(/PROVISIONING_REQUEST_IMMUTABLE/);
      expect(()=>f.sqlite.exec("DELETE FROM commission_provisioning_requests"))
        .toThrow(/PROVISIONING_REQUEST_IMMUTABLE/);
    }finally{f.close();}
  });
});
