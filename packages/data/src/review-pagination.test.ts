import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {
  listObservationPage,ObservationCursorError
} from "./review-pagination";
import {listObservationDrafts} from "./review";

function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('a','Comisión A','active'),('b','Comisión B','active'),('archived','Cerrada','closed');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('a','alice','member',1),('a','president','president',1),
      ('a','viewer','observer',1),('a','revoked','member',0),
      ('b','outside','member',1),('archived','reader','observer',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('b','a','Lote prueba');
    INSERT INTO checklist_items(id,commission_id,area,expected_document)
      VALUES('i','a','works','Documento sintético');
  `);
  const insert=f.sqlite.prepare(`
    INSERT INTO observations(id,commission_id,author_subject,title,description,status)
    VALUES(?,?,?,'Observación sintética','Evidencia de prueba','draft')
  `);
  const evidence=f.sqlite.prepare(`
    INSERT INTO observation_evidence(id,observation_id,type,reference_json)
    VALUES(?,?,'SEARCH_SCOPE',?)
  `);
  for(let i=0;i<65;i++) {
    const id=`obs_${String(i).padStart(3,"0")}`;
    insert.run(id,"a","alice");
    evidence.run(`e_${id}`,id,JSON.stringify({
      type:"SEARCH_SCOPE",commissionId:"a",checklistItemId:"i",batchId:"b",
      reviewerId:"alice",searchedAt:"2026-11-19T12:00:00.000Z"
    }));
    if(i%10===0) evidence.run(`e2_${id}`,id,JSON.stringify({
      type:"SEARCH_SCOPE",commissionId:"a",checklistItemId:"i",batchId:"b",
      reviewerId:"alice",searchedAt:"2026-11-19T12:30:00.000Z"
    }));
  }
  for(let i=0;i<7;i++) insert.run(`private_${i}`,"b","outside");
  return f;
}

describe("keyset paginated, tenant-scoped observation history",()=>{
  it("traverses all 65 records exactly once despite identical creation timestamps and multiple evidence rows",async()=>{
    const f=fixture();
    try {
      const seen:string[]=[];
      let cursor:string|null=null;
      const sizes:number[]=[];
      do {
        const page=await listObservationPage(f.db,"viewer","a",{cursor,limit:25});
        sizes.push(page.items.length);
        for(const item of page.items) {
          seen.push(item.id);
          expect(item.evidence).toHaveLength(item.id.endsWith("0")?2:1);
          expect(item.canSubmit).toBe(false);
          expect(item.canReview).toBe(false);
        }
        cursor=page.nextCursor;
        expect(sizes.length).toBeLessThanOrEqual(4);
      }while(cursor!==null);
      expect(sizes).toEqual([25,25,15]);
      expect(seen).toEqual(Array.from({length:65},(_,i)=>`obs_${String(64-i).padStart(3,"0")}`));
      const recent=await listObservationDrafts(f.db,"viewer","a");
      expect(recent).toHaveLength(50); // existing endpoint remains backward compatible
    }finally{f.close();}
  });

  it("does not duplicate older pages when newer records appear after the first page",async()=>{
    const f=fixture();
    try {
      const first=await listObservationPage(f.db,"alice","a",{limit:10});
      expect(first.items).toHaveLength(10);
      f.sqlite.prepare(`
        INSERT INTO observations(id,commission_id,author_subject,title,description)
        VALUES('obs_999','a','alice','Nuevo registro','Posterior a la primera página')
      `).run();
      const second=await listObservationPage(f.db,"alice","a",{
        cursor:first.nextCursor,limit:10
      });
      expect(second.items).toHaveLength(10);
      expect(new Set([...first.items,...second.items].map(r=>r.id)).size).toBe(20);
      expect(second.items.map(r=>r.id)).not.toContain("obs_999");
    }finally{f.close();}
  });

  it("preserves commission boundaries, active membership and closed commission access",async()=>{
    const f=fixture();
    try{
      const first=await listObservationPage(f.db,"alice","a",{limit:5});
      for(const who of ["outside","revoked","nobody"]){
        const result=await listObservationPage(f.db,who,"a",{limit:5});
        expect(result).toEqual({items:[],nextCursor:null});
      }
      expect((await listObservationPage(f.db,"outside","b",{limit:25})).items)
        .toHaveLength(7);
      await expect(listObservationPage(f.db,"outside","b",{
        cursor:first.nextCursor,limit:5
      })).rejects.toBeInstanceOf(ObservationCursorError);
      expect(await listObservationPage(f.db,"reader","archived"))
        .toEqual({items:[],nextCursor:null});
    }finally{f.close();}
  });

  it("uses a commission/order-aware index rather than sorting all observation statuses",()=>{
    const f=fixture();
    try {
      const plan=f.sqlite.prepare(`
        EXPLAIN QUERY PLAN SELECT id FROM observations
        WHERE commission_id='a'
        ORDER BY created_at DESC,id DESC LIMIT 25
      `).all() as Array<{detail:string}>;
      expect(plan.some(step=>step.detail.includes("idx_observations_history_keyset"))).toBe(true);
      expect(plan.some(step=>step.detail.includes("USE TEMP B-TREE FOR ORDER BY"))).toBe(false);
    }finally{f.close();}
  });

  it("rejects malformed, oversized, noncanonical and invalid-size cursors; never mutates audit",async()=>{
    const f=fixture();
    try{
      const before=f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get();
      for(const cursor of ["x","-".repeat(1000),"%20", "eyJ2Ijo5fQ","abc==="]){
        await expect(listObservationPage(f.db,"alice","a",{cursor}))
          .rejects.toBeInstanceOf(ObservationCursorError);
      }
      for(const limit of [0,51,-1,1.4,Number.NaN]){
        await expect(listObservationPage(f.db,"alice","a",{limit}))
          .rejects.toBeInstanceOf(ObservationCursorError);
      }
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual(before);
    }finally{f.close();}
  });
});
