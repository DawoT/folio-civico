import { describe,expect,it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { handleTextRequest } from "./text-routes";

const url="https://folio.test/api/commissions/c_a/documents/ver_a/pages";
function fixture(ready:boolean){
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('c_a','A','active'),('c_b','B','active');
    INSERT INTO commission_members(commission_id,subject,role,active)
      VALUES('c_a','alice','member',1),('c_a','observer','observer',1),
        ('c_a','revoked','member',0),('c_b','bob','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('b_a','c_a','Lote A');
    INSERT INTO documents(id,commission_id,batch_id,filename) VALUES('doc_a','c_a','b_a','Expediente.pdf');
    INSERT INTO document_versions(id,document_id,version_number,sha256,r2_object_key)
      VALUES('ver_a','doc_a',1,'${"a".repeat(64)}','quarantine/secret.pdf');
  `);
  if(ready){
    f.sqlite.exec(`
      INSERT INTO document_processing_reports(document_version_id,scanner_name,scanner_report_id,
        scanned_at,source_sha256,manifest_sha256,page_count)
      VALUES('ver_a','isolated-scanner','test_report_12345',
        '2026-11-18T17:30:00.000Z','${"a".repeat(64)}','${"b".repeat(64)}',2);
      INSERT INTO document_pages(document_version_id,page,extracted_text,extraction_status)
      VALUES('ver_a',1,'Página de prueba','ready'),('ver_a',2,'Página segunda','ready');
      UPDATE document_versions SET page_count=2,extraction_status='ready' WHERE id='ver_a';
    `);
  }
  return f;
}
describe("read-only processed text endpoint",()=>{
  it("denies pending documents even to members and has no raw R2 endpoint",async()=>{
    const f=fixture(false);
    try {
      const result=await handleTextRequest(new Request(url),{DB:f.db},"alice","c_a","ver_a");
      expect(result.status).toBe(404);
      expect(result.headers.get("Cache-Control")).toContain("no-store");
    }finally{f.close();}
  });
  it("returns escaped-as-data text and page-level provenance only to members",async()=>{
    const f=fixture(true);
    try {
      const result=await handleTextRequest(new Request(url),{DB:f.db},"alice","c_a","ver_a");
      expect(result.status).toBe(200);
      const parsed=await result.json();
      expect(parsed).toMatchObject({versionId:"ver_a",pageCount:2,
        pages:[{page:1,text:"Página de prueba"},{page:2,text:"Página segunda"}]});
      expect(JSON.stringify(parsed)).not.toContain("quarantine/secret.pdf");
      expect(JSON.stringify(parsed)).not.toContain("scanner_report");
      expect(result.headers.get("Cache-Control")).toContain("no-store");
      expect(result.headers.get("X-Content-Type-Options")).toBe("nosniff");
      for(const subject of ["bob","revoked","unknown"]) {
        expect((await handleTextRequest(new Request(url),{DB:f.db},subject,"c_a","ver_a")).status).toBe(404);
      }
      expect((await handleTextRequest(new Request(url),{DB:f.db},"observer","c_a","ver_a")).status).toBe(200);
      expect((await handleTextRequest(new Request(url),{DB:f.db},"alice","c_b","ver_a")).status).toBe(404);
    }finally{f.close();}
  });
  it("does not return inspected page text when membership is revoked after pages load",async()=>{
    const f=fixture(true);
    try {
      let injected=false;
      const raced={
        prepare(sql:string){
          const statement=f.db.prepare(sql);
          if(!sql.includes("SELECT p.page,p.extracted_text AS text")) return statement;
          return {
            bind(...args:unknown[]){
              const bound=statement.bind(...args);
              return {
                async all<T>(){
                  const result=await bound.all<T>();
                  if(!injected){
                    injected=true;
                    f.sqlite.exec("UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='alice'");
                  }
                  return result;
                }
              };
            }
          } as unknown as D1PreparedStatement;
        }
      } as D1Database;
      const res=await handleTextRequest(new Request(url),{DB:raced},"alice","c_a","ver_a");
      expect(injected).toBe(true);
      expect(res.status).toBe(404);
      expect(await res.json()).toEqual({error:"Not found"});
      expect(res.headers.get("Cache-Control")).toContain("no-store");
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual({n:0});
    } finally {f.close();}
  });

  it("denies inspected pages if the last membership lookup fails",async()=>{
    const f=fixture(true);
    try {
      let lastProbe=0;
      const failing={
        prepare(sql:string) {
          if(sql.includes("SELECT c.id, c.name, c.status, m.role") && ++lastProbe===1){
            throw new Error("PRIVATE_DB_CONNECTION");
          }
          return f.db.prepare(sql);
        }
      } as D1Database;
      const res=await handleTextRequest(new Request(url),{DB:failing},"alice","c_a","ver_a");
      expect(lastProbe).toBe(1);
      expect(res.status).toBe(503);
      expect(await res.json()).toEqual({error:"Unable to retrieve inspected text"});
      expect(res.headers.get("Cache-Control")).toContain("no-store");
    }finally{f.close();}
  });

  it("keeps inspected pages readable to an active member after commission closure",async()=>{
    const f=fixture(true);
    try {
      f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
      const res=await handleTextRequest(new Request(url),{DB:f.db},"alice","c_a","ver_a");
      expect(res.status).toBe(200);
      expect(await res.json()).toMatchObject({pageCount:2,pages:[{page:1,text:"Página de prueba"},{page:2,text:"Página segunda"}]});
    }finally{f.close();}
  });

  it("never accepts mutation methods for page content",async()=>{
    const f=fixture(true);
    try {
      const response=await handleTextRequest(new Request(url,{method:"POST",
        body:"tamper"}),{DB:f.db},"alice","c_a","ver_a");
      expect(response.status).toBe(405);
    }finally{f.close();}
  });
});
