import { describe, expect, it, vi } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import worker from "./index";
import { runQuarantineAudit } from "./maintenance";

describe("operator-only audit entrypoint", () => {
  function fixture() {
    const f=makeD1();
    const key="quarantine/internal-only.pdf";
    const listing={objects:[{key,uploaded:new Date("2026-11-01T00:00:00.000Z")}],truncated:false};
    const list=vi.fn(async()=>listing);
    const head=vi.fn(async()=>null);
    const deleteObject=vi.fn(async()=>{throw Error("Unexpected deletion");});
    return {...f,key,list,head,deleteObject,bucket:{
      list,head,delete:deleteObject
    } as unknown as R2Bucket};
  }

  it("emits only aggregate statistics, with no keys, hashes or document content", async()=>{
    const f=fixture();
    const emit=vi.fn();
    try {
      const result=await runQuarantineAudit({DB:f.db,DOCUMENTS:f.bucket},emit,{
        now:new Date("2026-11-18T12:00:00Z"),maxPages:1,pageSize:10,maxReferences:10
      });
      expect(result).toMatchObject({orphanCandidates:1,complete:true,integrityVerified:false});
      expect(emit).toHaveBeenCalledOnce();
      expect(JSON.stringify(emit.mock.calls)).not.toContain(f.key);
      expect(JSON.stringify(emit.mock.calls)).not.toContain("keyFingerprint");
      expect(f.deleteObject).not.toHaveBeenCalled();
    }finally{f.close();}
  });

  it("refuses missing bindings and does not emit a misleading summary",async()=>{
    const emit=vi.fn();
    await expect(runQuarantineAudit({},emit)).rejects.toThrow("bindings");
    expect(emit).not.toHaveBeenCalled();
  });

  it("supports the dormant scheduled handler without an HTTP route",async()=>{
    const f=fixture();
    const log=vi.spyOn(console,"log").mockImplementation(()=>undefined);
    const promises:Promise<unknown>[]=[];
    try {
      const ctx={waitUntil(p:Promise<unknown>){promises.push(p);}} as unknown as ExecutionContext;
      worker.scheduled({} as ScheduledController,{DB:f.db,DOCUMENTS:f.bucket},ctx);
      await Promise.all(promises);
      expect(log).toHaveBeenCalledTimes(1);
      expect(log.mock.calls[0]?.[0]).toContain("folio.quarantine.audit");
      expect(log.mock.calls[0]?.[0]).not.toContain(f.key);
      expect(f.deleteObject).not.toHaveBeenCalled();
    }finally{log.mockRestore();f.close();}
  });
});
