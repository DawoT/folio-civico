import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {handleReviewRequest} from "./review-routes";

function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('a','Comisión A','active'),('b','Comisión B','active');
    INSERT INTO commission_members(commission_id,subject,role,active)
      VALUES('a','alice','member',1),('a','reader','observer',1),
        ('a','revoked','member',0),('b','outsider','member',1);
  `);
  const insert=f.sqlite.prepare(`
    INSERT INTO observations(id,commission_id,author_subject,title,description)
    VALUES(?,?,'alice','Búsqueda del expediente','Observación sintética')
  `);
  for(let i=0;i<56;i++) insert.run(`obs_${String(i).padStart(3,"0")}`,"a");
  return f;
}
const base="https://folio.test/api/commissions/a/observations";
const request=(query="")=>new Request(base+"/history"+query);

describe("authorized observation history API",()=>{
  it("returns keyset pages with a stable cursor and no-cache protections",async()=>{
    const f=fixture();
    try {
      const first=await handleReviewRequest(request("?limit=25"),{DB:f.db},"reader","a","history");
      expect(first.status).toBe(200);
      expect(first.headers.get("Cache-Control")).toBe("no-store");
      const page=await first.json() as {items:Array<{id:string;canSubmit:boolean}>;nextCursor:string|null};
      expect(page.items).toHaveLength(25);
      expect(page.items[0]).toMatchObject({id:"obs_055",canSubmit:false});
      expect(page.nextCursor).toBeTruthy();
      const second=await handleReviewRequest(request("?limit=25&cursor="+page.nextCursor),{DB:f.db},"reader","a","history");
      expect(second.status).toBe(200);
      const next=await second.json() as typeof page;
      expect(next.items).toHaveLength(25);
      expect(new Set([...page.items,...next.items].map(r=>r.id)).size).toBe(50);
      const third=await handleReviewRequest(request("?limit=25&cursor="+next.nextCursor),{DB:f.db},"reader","a","history");
      const final=await third.json() as typeof page;
      expect(final.items).toHaveLength(6);
      expect(final.nextCursor).toBeNull();
    }finally{f.close();}
  });
  it("denies membership leaks and cursor substitution, invalid sizes and unexpected filters",async()=>{
    const f=fixture();
    try {
      for(const who of ["revoked","outsider","unknown"]) {
        expect((await handleReviewRequest(request(),{DB:f.db},who,"a","history")).status).toBe(404);
      }
      for(const query of ["?limit=0","?limit=51","?limit=1.5","?status=draft",
        "?limit=25&limit=25","?cursor=","?cursor=not-a-cursor"]) {
        expect((await handleReviewRequest(request(query),{DB:f.db},"alice","a","history")).status).toBe(400);
      }
      expect((await handleReviewRequest(new Request(base+"/history",{method:"POST"}),
        {DB:f.db},"alice","a","history")).status).toBe(405);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:0});
    }finally{f.close();}
  });
});
