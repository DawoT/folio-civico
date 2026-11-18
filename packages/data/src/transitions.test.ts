import { describe,expect,it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { persistDraftObservation, listObservationDrafts } from "./review";
import { transitionObservation } from "./transitions";

const requestKey="review_action_12345";
function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES ('c_a','A','active'),('c_b','B','active'),('closed','Closed','closed');
    INSERT INTO commission_members(commission_id,subject,role,active)
      VALUES ('c_a','author','member',1),('c_a','reviewer','president',1),
      ('c_a','advisor','advisor',1),('c_a','observer','observer',1),
      ('c_a','revoked','president',0),('c_b','outsider','president',1),
      ('closed','closed_reviewer','president',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('b_a','c_a','Obras');
    INSERT INTO checklist_items(id,commission_id,area,expected_document)
      VALUES('item_a','c_a','works','Expediente');
  `);
  return f;
}
async function createDraft(db:D1Database) {
  return persistDraftObservation(db,{
    commissionId:"c_a",authorSubject:"author",title:"Documento no ubicado",
    description:"Búsqueda manual en el expediente del lote.",
    evidence:[{type:"SEARCH_SCOPE",commissionId:"c_a",checklistItemId:"item_a",
      batchId:"b_a",reviewerId:"author",searchedAt:"2026-11-18T13:00:00.000Z"}]
  });
}
describe("manual observation transitions",()=>{
  it("requires submit and a separate authorized reviewer, with exactly two audited transitions",async()=>{
    const f=fixture();
    try {
      const draft=await createDraft(f.db);
      expect(await listObservationDrafts(f.db,"author","c_a")).toMatchObject([{canSubmit:true,canReview:false}]);
      const submitted=await transitionObservation(f.db,{commissionId:"c_a",subject:"author",
        observationId:draft.id,action:"submit",requestKey});
      expect(submitted.observation.status).toBe("in_review");
      expect(submitted.replayed).toBe(false);
      expect(await listObservationDrafts(f.db,"author","c_a")).toMatchObject([{canSubmit:false,canReview:false}]);
      expect(await listObservationDrafts(f.db,"reviewer","c_a")).toMatchObject([{canSubmit:false,canReview:true}]);
      const reviewed=await transitionObservation(f.db,{commissionId:"c_a",subject:"reviewer",
        observationId:draft.id,action:"validate",note:"Confirmé manualmente el alcance de búsqueda.",
        requestKey:"validate_req_12345"});
      expect(reviewed.observation.status).toBe("validated");
      expect(reviewed.observation.validatedBy).toBe("reviewer");
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:3});
      expect(f.sqlite.prepare("SELECT status,reviewed_by,review_note FROM observations WHERE id=?").get(draft.id))
        .toMatchObject({status:"validated",reviewed_by:"reviewer",review_note:"Confirmé manualmente el alcance de búsqueda."});
    } finally {f.close();}
  });

  it("replays submit and validation once but rejects altered rationale or key",async()=>{
    const f=fixture();
    try {
      const draft=await createDraft(f.db);
      const input={commissionId:"c_a",subject:"author",observationId:draft.id,action:"submit" as const,requestKey};
      await transitionObservation(f.db,input);
      expect((await transitionObservation(f.db,input)).replayed).toBe(true);
      await expect(transitionObservation(f.db,{...input,requestKey:"different_key_12"})).rejects.toThrow();
      const final={commissionId:"c_a",subject:"reviewer",observationId:draft.id,action:"dismiss" as const,
        note:"No corresponde sostener esta observación.",requestKey:"dismiss_key_123"};
      await transitionObservation(f.db,final);
      expect((await transitionObservation(f.db,final)).replayed).toBe(true);
      await expect(transitionObservation(f.db,{...final,note:"Razón diferente y suficiente."})).rejects.toThrow();
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:3});
    } finally {f.close();}
  });

  it("denies self approval, advisor, observer, revoked and cross commission",async()=>{
    const f=fixture();
    try {
      const draft=await createDraft(f.db);
      await expect(transitionObservation(f.db,{commissionId:"c_a",subject:"reviewer",
        observationId:draft.id,action:"submit",requestKey})).rejects.toThrow();
      await transitionObservation(f.db,{commissionId:"c_a",subject:"author",
        observationId:draft.id,action:"submit",requestKey});
      for(const subject of ["author","advisor","observer","revoked","outsider"]) {
        await expect(transitionObservation(f.db,{commissionId:"c_a",subject,
          observationId:draft.id,action:"validate",note:"Constatación manual satisfactoria.",
          requestKey:"approval_req_123"})).rejects.toThrow();
      }
      expect(f.sqlite.prepare("SELECT status FROM observations WHERE id=?").get(draft.id))
        .toMatchObject({status:"in_review"});
    } finally {f.close();}
  });

  it("prevents direct SQL from bypassing review rules or editing validated evidence",async()=>{
    const f=fixture();
    try {
      const draft=await createDraft(f.db);
      expect(()=>f.sqlite.prepare("UPDATE observations SET status='validated',validated_by='author',validated_at=CURRENT_TIMESTAMP WHERE id=?").run(draft.id)).toThrow();
      expect(()=>f.sqlite.prepare("UPDATE observations SET validated_by='reviewer' WHERE id=?").run(draft.id))
        .toThrow(/REVIEW_METADATA_IMMUTABLE/);
      expect(()=>f.sqlite.prepare("UPDATE observations SET draft_request_key='forged_request' WHERE id=?").run(draft.id))
        .toThrow(/REVIEW_METADATA_IMMUTABLE/);
      await transitionObservation(f.db,{commissionId:"c_a",subject:"author",observationId:draft.id,action:"submit",requestKey});
      expect(()=>f.sqlite.prepare(
        "INSERT INTO observation_evidence(id,observation_id,type,reference_json) VALUES(?,?,?,?)"
      ).run("later_proof",draft.id,"SEARCH_SCOPE",JSON.stringify({
        type:"SEARCH_SCOPE",commissionId:"c_a",checklistItemId:"item_a",
        batchId:"b_a",reviewerId:"author",searchedAt:"2026-11-18T17:00:00.000Z"
      }))).toThrow(/EVIDENCE_LOCKED_AFTER_SUBMISSION/);
      expect(()=>f.sqlite.prepare("UPDATE observations SET status='validated',reviewed_by='author',review_note='Unilateral',validated_by='author',validated_at=CURRENT_TIMESTAMP WHERE id=?").run(draft.id)).toThrow();
      expect(f.sqlite.prepare("SELECT status FROM observations WHERE id=?").get(draft.id)).toMatchObject({status:"in_review"});
    } finally {f.close();}
  });

  it("denies stale evidence before approval and closed commissions",async()=>{
    const f=fixture();
    try {
      const draft=await createDraft(f.db);
      await transitionObservation(f.db,{commissionId:"c_a",subject:"author",observationId:draft.id,action:"submit",requestKey});
      f.sqlite.exec("UPDATE checklist_items SET status='located' WHERE id='item_a'");
      await expect(transitionObservation(f.db,{commissionId:"c_a",subject:"reviewer",
        observationId:draft.id,action:"validate",note:"Revisión con referencia obsoleta.",
        requestKey:"validate_key_123"})).rejects.toThrow();
      f.sqlite.exec("UPDATE checklist_items SET status='pending' WHERE id='item_a'");
      f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
      await expect(transitionObservation(f.db,{commissionId:"c_a",subject:"reviewer",
        observationId:draft.id,action:"dismiss",note:"Comisión cerrada para decisiones.",
        requestKey:"dismiss_key_456"})).rejects.toThrow();
    } finally {f.close();}
  });
});
