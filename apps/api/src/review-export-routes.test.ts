import { describe, expect, it, vi } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { makeD1 } from "../../../tests/helpers/d1";
import { persistDraftObservation, transitionObservation } from "@folio/data";
import { handleReviewExportRequest } from "./review-export-routes";

function fixture() {
  const f = makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('commission_a','Comisión A','active'),('commission_b','Comisión B','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('commission_a','author','member',1),('commission_a','reviewer','president',1),
      ('commission_a','reader','observer',1),('commission_a','revoked','member',0),
      ('commission_b','outsider','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('batch_a','commission_a','Obras');
    INSERT INTO checklist_items(id,commission_id,area,expected_document)
      VALUES('item_a','commission_a','works','Expediente');
  `);
  return f;
}
async function finalized(db:D1Database) {
  const record=await persistDraftObservation(db,{
    commissionId:"commission_a",authorSubject:"author",title:"Expediente no ubicado",
    description:"La búsqueda documentada no encontró este expediente.",
    evidence:[{type:"SEARCH_SCOPE",commissionId:"commission_a",checklistItemId:"item_a",
      batchId:"batch_a",reviewerId:"author",searchedAt:"2026-11-18T13:00:00.000Z"}]
  });
  await transitionObservation(db,{commissionId:"commission_a",subject:"author",observationId:record.id,
    action:"submit",requestKey:"submit_export_12345"});
  await transitionObservation(db,{commissionId:"commission_a",subject:"reviewer",observationId:record.id,
    action:"validate",requestKey:"validate_export_12345",
    note:"Revisé los documentos y el alcance de la búsqueda realizada."});
  return record;
}
const base="https://folio.test/api/commissions/commission_a/observations/export";
describe("finalized observations export API",()=>{
  it("returns a complete no-cache download with verifiable SHA-256 and zero original PDF bytes",async()=>{
    const f=fixture();
    try {
      const record=await finalized(f.db);
      const response=await handleReviewExportRequest(new Request(base),{DB:f.db},"reader","commission_a");
      expect(response.status).toBe(200);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.get("Content-Disposition")).toMatch(/attachment/);
      expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
      const report=await response.json() as {format:string;sha256:string;payload:string};
      expect(report.format).toBe("folio-civico.review-export.v1");
      const actual = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",
        new TextEncoder().encode(report.payload))),byte=>byte.toString(16).padStart(2,"0")).join("");
      expect(actual).toBe(report.sha256);
      const body=JSON.parse(report.payload) as {
        observations: Array<{id:string;status:string;evidence:unknown[]}>;
        completeness:{included:number;truncated:boolean};disclaimer:string
      };
      expect(body.observations).toMatchObject([{id:record.id,status:"validated",
        evidence:[{type:"SEARCH_SCOPE",reviewerId:"author",checklistItemId:"item_a"}]}]);
      expect(body.completeness).toMatchObject({included:1,truncated:false});
      expect(body.disclaimer).toMatch(/no constituye/i);
      expect(response.headers.get("X-Report-SHA256")).toBe(report.sha256);
      expect(JSON.stringify(report)).not.toContain("quarantine/");
      expect(JSON.stringify(report)).not.toContain("requestKey");
    } finally {f.close();}
  });

  it("produces an actual archive accepted by the independent offline verifier",async()=>{
    const f=fixture();
    const directory=mkdtempSync(join(tmpdir(),"folio-report-real-"));
    try {
      await finalized(f.db);
      const response=await handleReviewExportRequest(new Request(base),{DB:f.db},"reader","commission_a");
      expect(response.status).toBe(200);
      const file=join(directory,"export.json");
      writeFileSync(file,await response.text(),"utf8");
      const verification=spawnSync(process.execPath,["scripts/verify-review-export.mjs",file],{
        encoding:"utf8",timeout:5000
      });
      expect(verification.status).toBe(0);
      expect(verification.stdout).toMatch(/registros: 1/);
    } finally {
      rmSync(directory,{recursive:true,force:true});
      f.close();
    }
  });

  it.each([
    ["unrecognized evidence type", JSON.stringify({ type: "UNKNOWN", commissionId: "commission_a" })],
    ["missing evidence join", null],
    ["malformed evidence date", JSON.stringify({
      type: "SEARCH_SCOPE", commissionId: "commission_a", checklistItemId: "item_a",
      batchId: "batch_a", reviewerId: "author", searchedAt: "yesterday"
    })]
  ])("never signs a review export with %s", async (_label, corruptedEvidence) => {
    const f = fixture();
    try {
      await finalized(f.db);
      // Simulate corrupt/past-migration D1 rows without bypassing database
      // immutability triggers on finalized records.
      const corrupted = {
        prepare: (sql: string) => {
          const statement = f.db.prepare(sql);
          if (!sql.includes("WITH picked AS")) return statement;
          return {
            bind: (...params: Parameters<typeof statement.bind>) => {
              const query = statement.bind(...params);
              return {
                all: async () => {
                  const rows = await query.all<Record<string, unknown>>();
                  return { ...rows, results: rows.results.map(row => ({
                    ...row, evidenceJson: corruptedEvidence
                  })) };
                }
              };
            }
          };
        }
      } as unknown as D1Database;
      const response = await handleReviewExportRequest(
        new Request(base), { DB: corrupted }, "reader", "commission_a"
      );
      expect(response.status).toBe(503);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(response.headers.get("Content-Disposition")).toBeNull();
      expect(response.headers.get("X-Report-SHA256")).toBeNull();
      expect(await response.json()).toEqual({ error: "Report could not be generated" });
    } finally { f.close(); }
  });

  it("returns 404 without exporting committee metadata when membership is revoked mid-query",async()=>{
    const f=fixture();
    try{
      await finalized(f.db);
      let revoked=false;
      const db={
        prepare:(sql:string)=>{
          const statement=f.db.prepare(sql);
          if(!sql.includes("WITH picked AS"))return statement;
          return {
            bind:(...values:Parameters<typeof statement.bind>)=>{
              const bound=statement.bind(...values);
              return {
                all:async()=>{
                  const rows=await bound.all();
                  f.sqlite.prepare(
                    "UPDATE commission_members SET active=0 WHERE commission_id='commission_a' AND subject='reader'"
                  ).run();
                  revoked=true;
                  return rows;
                }
              };
            }
          };
        }
      } as unknown as D1Database;
      const response=await handleReviewExportRequest(new Request(base),{DB:db},"reader","commission_a");
      expect(revoked).toBe(true);
      expect(response.status).toBe(404);
      expect(response.headers.get("Content-Disposition")).toBeNull();
      const body=await response.text();
      expect(body).not.toContain("Comisión A");
      expect(body).not.toContain("Expediente no ubicado");
      expect(response.headers.get("Cache-Control")).toBe("no-store");
    }finally{f.close();}
  });

  it("returns 404 without a download if access is revoked while SHA-256 is pending",async()=>{
    const f=fixture();
    const originalDigest=crypto.subtle.digest.bind(crypto.subtle);
    let revoked=false;
    try {
      await finalized(f.db);
      const digestSpy=vi.spyOn(crypto.subtle,"digest").mockImplementation(async(algorithm,data)=>{
        const hash=await originalDigest(algorithm,data);
        f.sqlite.prepare(
          "UPDATE commission_members SET active=0 WHERE commission_id='commission_a' AND subject='reader'"
        ).run();
        revoked=true;
        return hash;
      });
      try {
        const response=await handleReviewExportRequest(
          new Request(base),{DB:f.db},"reader","commission_a"
        );
        expect(revoked).toBe(true);
        expect(response.status).toBe(404);
        expect(response.headers.get("Content-Disposition")).toBeNull();
        expect(response.headers.get("X-Report-SHA256")).toBeNull();
        const body=await response.text();
        expect(body).not.toContain("Comisión A");
        expect(body).not.toContain("Expediente no ubicado");
      }finally{digestSpy.mockRestore();}
    }finally{f.close();}
  });

  it("denies cross-commission, revoked identities, mutation methods and filters",async()=>{
    const f=fixture();
    try {
      await finalized(f.db);
      for(const who of ["outsider","revoked","unknown"]) {
        expect((await handleReviewExportRequest(new Request(base),{DB:f.db},who,"commission_a")).status).toBe(404);
      }
      expect((await handleReviewExportRequest(new Request(base,{method:"DELETE"}),{DB:f.db},"reader","commission_a")).status).toBe(405);
      expect((await handleReviewExportRequest(new Request(base+"?status=draft"),{DB:f.db},"reader","commission_a")).status).toBe(400);
    } finally {f.close();}
  });
});
