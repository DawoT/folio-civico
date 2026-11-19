import { describe, expect, it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { persistDraftObservation, transitionObservation } from "./index";
import { collectFinalizedReviews, ReviewExportLimitError } from "./review-export";

function fixture() {
  const f = makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('c_a','Comisión Obras','active'),('c_b','Otro municipio','active'),('c_closed','Cerrada','closed');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('c_a','author','member',1),('c_a','reviewer','president',1),
      ('c_a','viewer','observer',1),('c_a','revoked','member',0),
      ('c_b','other','president',1),('c_closed','viewer','observer',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('batch_a','c_a','Obras');
    INSERT INTO checklist_items(id,commission_id,area,expected_document) VALUES
      ('expected_a','c_a','works','Expediente de obra');
  `);
  return f;
}
async function makeDraft(db: D1Database, title="No ubicado") {
  return persistDraftObservation(db,{
    commissionId:"c_a",authorSubject:"author",title,
    description:"Se revisó el lote y no apareció el documento solicitado.",
    evidence:[{type:"SEARCH_SCOPE",commissionId:"c_a",checklistItemId:"expected_a",
      batchId:"batch_a",reviewerId:"author",searchedAt:"2026-11-18T14:00:00.000Z"}]
  });
}
async function decide(db:D1Database,id:string,action:"validate"|"dismiss",suffix:string) {
  await transitionObservation(db,{commissionId:"c_a",subject:"author",
    observationId:id,action:"submit",requestKey:"submit_"+suffix+"_12345"});
  await transitionObservation(db,{commissionId:"c_a",subject:"reviewer",
    observationId:id,action,requestKey:"review_"+suffix+"_12345",
    note:"He cotejado el alcance de la búsqueda registrada y sus fuentes."});
}

describe("complete, tenant-scoped export of finalized human reviews",()=>{
  it("includes validated and dismissed decisions, evidence and reviewer, but never drafts or request keys",async()=>{
    const f=fixture();
    try {
      const valid=await makeDraft(f.db,"Validado");
      await decide(f.db,valid.id,"validate","one");
      const discarded=await makeDraft(f.db,"Descartado");
      await decide(f.db,discarded.id,"dismiss","two");
      await makeDraft(f.db,"Borrador privado");
      const result=await collectFinalizedReviews(f.db,"viewer","c_a");
      if (!result) throw new Error("Authorized commission must be accessible");
      expect(result.commission).toMatchObject({id:"c_a",name:"Comisión Obras"});
      expect(result.records).toHaveLength(2);
      expect(result.records.map(record=>record.status).sort()).toEqual(["dismissed","validated"]);
      expect(result.records.find(record=>record.id===valid.id)).toMatchObject({
        title:"Validado",authorSubject:"author",reviewedBy:"reviewer",
        evidence:[{type:"SEARCH_SCOPE",commissionId:"c_a",checklistItemId:"expected_a"}]
      });
      expect(JSON.stringify(result)).not.toContain("submitRequestKey");
      expect(JSON.stringify(result)).not.toContain("reviewRequestKey");
      expect(JSON.stringify(result)).not.toContain("Borrador privado");
    } finally {f.close();}
  });

  it("denies non-members, revoked subjects and cross-commission reads even with identical IDs",async()=>{
    const f=fixture();
    try {
      const record=await makeDraft(f.db);
      await decide(f.db,record.id,"validate","one");
      for(const who of ["other","revoked","unknown"]) {
        await expect(collectFinalizedReviews(f.db,who,"c_a")).resolves.toBeNull();
      }
      const other=await collectFinalizedReviews(f.db,"other","c_b");
      expect(other?.records).toEqual([]);
      const closed=await collectFinalizedReviews(f.db,"viewer","c_closed");
      expect(closed?.records).toEqual([]);
    } finally {f.close();}
  });

  it("does not silently truncate beyond the exact per-export maximum",async()=>{
    const f=fixture();
    try {
      const record=await makeDraft(f.db);
      await decide(f.db,record.id,"validate","one");
      await expect(collectFinalizedReviews(f.db,"viewer","c_a",0)).rejects.toBeInstanceOf(ReviewExportLimitError);
      expect((await collectFinalizedReviews(f.db,"viewer","c_a",1))?.records).toHaveLength(1);
      const second=await makeDraft(f.db,"Segundo expediente");
      await decide(f.db,second.id,"dismiss","two");
      await expect(collectFinalizedReviews(f.db,"viewer","c_a",1))
        .rejects.toBeInstanceOf(ReviewExportLimitError);
    } finally {f.close();}
  });

  it("read-only export does not mutate D1 or append audit events",async()=>{
    const f=fixture();
    try {
      const record=await makeDraft(f.db);
      await decide(f.db,record.id,"validate","one");
      const before=f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get();
      await collectFinalizedReviews(f.db,"viewer","c_a");
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual(before);
    } finally {f.close();}
  });
});
