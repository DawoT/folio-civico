import {describe,expect,it} from "vitest";
import {performance} from "node:perf_hooks";
import {makeD1} from "./helpers/d1";
import {getCommissionSummary} from "../packages/data/src/commissions";

function percentile(sorted:number[],fraction:number):number {
  return sorted[Math.max(0,Math.ceil(sorted.length*fraction)-1)]!;
}

describe("S01-02 local D1 access fence cost (diagnostic, no latency SLO)",()=>{
  it("measures one additional scoped membership query using a real local SQLite D1 adapter",async()=>{
    const f=makeD1();
    try {
      f.sqlite.exec(`
        INSERT INTO commissions(id,name) VALUES('bench_a','Synthetic commission');
        INSERT INTO commission_members(commission_id,subject,role,active)
        VALUES('bench_a','test-member','member',1);
      `);
      // Warm the local SQLite driver; never treat these timings as Cloudflare D1 RTT.
      for(let i=0;i<30;i++) {
        expect(await getCommissionSummary(f.db,"test-member","bench_a"))
          .toMatchObject({role:"member"});
      }
      const samples:number[]=[];
      for(let i=0;i<200;i++){
        const before=performance.now();
        const membership=await getCommissionSummary(f.db,"test-member","bench_a");
        const elapsed=performance.now()-before;
        expect(membership).toMatchObject({id:"bench_a",role:"member"});
        expect(Number.isFinite(elapsed) && elapsed>=0).toBe(true);
        samples.push(elapsed);
      }
      const ordered=samples.sort((a,b)=>a-b);
      const report={
        environment:"local-sqlite-d1-adapter-no-network",
        additionalQueriesPerFencedRead:1,
        warmups:30,
        samples:200,
        medianMs:Number(percentile(ordered,.5).toFixed(4)),
        p95Ms:Number(percentile(ordered,.95).toFixed(4))
      };
      expect(report.samples).toBe(200);
      expect(report.medianMs).toBeGreaterThanOrEqual(0);
      expect(report.p95Ms).toBeGreaterThanOrEqual(report.medianMs);
      console.log("S01 D1 LOCAL FENCE BENCHMARK: "+JSON.stringify(report));
    }finally{f.close();}
  });
});
