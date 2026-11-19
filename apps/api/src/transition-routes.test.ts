import { describe,expect,it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { persistDraftObservation } from "@folio/data";
import { handleTransitionRequest } from "./transition-routes";
import { handleReviewRequest } from "./review-routes";

function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('c_a','A','active'),('c_b','B','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('c_a','alice','member',1),('c_a','eva','president',1),
      ('c_a','advisor','advisor',1),('c_a','viewer','observer',1),
      ('c_b','bob','president',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('b_a','c_a','Obras');
    INSERT INTO checklist_items(id,commission_id,area,expected_document)
      VALUES('item_a','c_a','works','Expediente');
  `);
  return f;
}

async function draft(db:D1Database) {
  return persistDraftObservation(db,{
    commissionId:"c_a",authorSubject:"alice",title:"Archivo no ubicado",
    description:"El expediente esperado no se ubicó en este lote.",
    evidence:[{type:"SEARCH_SCOPE",commissionId:"c_a",checklistItemId:"item_a",
      batchId:"b_a",reviewerId:"alice",searchedAt:"2026-11-18T15:00:00.000Z"}]
  });
}
const base="https://folio.test/api/commissions/c_a";
function post(id:string, action:string, note?:string, opts:{key?:string;origin?:string}={}) {
  const data=note===undefined?{action}:{action,note};
  return new Request(`${base}/observations/${id}/actions`,{
    method:"POST",headers:{
      "Content-Type":"application/json",
      "Idempotency-Key":opts.key??"transition_key_12345",
      ...(opts.origin?{Origin:opts.origin}:{})
    },body:JSON.stringify(data)
  });
}

describe("human decision API",()=>{
  it("submits, then validates by a distinct president; replay is not a second audit",async()=>{
    const f=fixture();
    try {
      const obs=await draft(f.db);
      const submitted=await handleTransitionRequest(post(obs.id,"submit"),{DB:f.db},"alice","c_a",obs.id);
      expect(submitted.status).toBe(200);
      expect(await submitted.json()).toMatchObject({status:"in_review",replayed:false});
      const note="He revisado personalmente la evidencia y el alcance.";
      const decision=await handleTransitionRequest(post(obs.id,"validate",note,{key:"validate_key_123"}),{DB:f.db},"eva","c_a",obs.id);
      expect(decision.status).toBe(200);
      expect(await decision.json()).toMatchObject({status:"validated",validatedBy:"eva"});
      const replay=await handleTransitionRequest(post(obs.id,"validate",note,{key:"validate_key_123"}),{DB:f.db},"eva","c_a",obs.id);
      expect(replay.status).toBe(200);
      expect(await replay.json()).toMatchObject({replayed:true});
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:3});
    } finally {f.close();}
  });

  it("exposes confirmed absence through the authorized checklist endpoint only after two-person validation",async()=>{
    const f=fixture();
    try {
      const obs=await draft(f.db);
      const getChecklist=async (subject:string) => handleReviewRequest(
        new Request(base+"/checklist"),{DB:f.db},subject,"c_a","checklist");
      expect(await (await getChecklist("alice")).json()).toMatchObject([
        {id:"item_a",status:"pending",statusSource:"stored",validatedSearchObservationId:null}
      ]);
      await handleTransitionRequest(post(obs.id,"submit"),{DB:f.db},"alice","c_a",obs.id);
      expect(await (await getChecklist("eva")).json()).toMatchObject([{status:"pending"}]);
      const result=await handleTransitionRequest(
        post(obs.id,"validate","Verifiqué personalmente el alcance de esta búsqueda.",{key:"confirm_12345"}),
        {DB:f.db},"eva","c_a",obs.id
      );
      expect(result.status).toBe(200);
      const checklist=await getChecklist("eva");
      expect(checklist.headers.get("Cache-Control")).toBe("no-store");
      expect(await checklist.json()).toMatchObject([
        {id:"item_a",status:"not_located",statusSource:"validated_search",
          validatedSearchObservationId:obs.id,reviewedBy:"eva"}
      ]);
      expect((await getChecklist("bob")).status).toBe(404);
    } finally {f.close();}
  });

  it("denies self-review, unauthorized roles and cross commission observation",async()=>{
    const f=fixture();
    try {
      const obs=await draft(f.db);
      await handleTransitionRequest(post(obs.id,"submit"),{DB:f.db},"alice","c_a",obs.id);
      const rationale="Esta observación fue revisada y requiere validación.";
      for(const subject of ["alice","advisor","viewer","bob"]) {
        expect((await handleTransitionRequest(post(obs.id,"validate",rationale),{DB:f.db},subject,"c_a",obs.id)).status).toBe(subject==="bob"?404:403);
      }
      expect((await handleTransitionRequest(post("other_id","validate",rationale),{DB:f.db},"eva","c_a","other_id")).status).toBe(404);
    } finally {f.close();}
  });

  it("rejects unsafe origins, forged actor fields, missing key and premature decisions",async()=>{
    const f=fixture();
    try {
      const obs=await draft(f.db);
      expect((await handleTransitionRequest(post(obs.id,"submit",undefined,{origin:"https://evil.test"}),{DB:f.db},"alice","c_a",obs.id)).status).toBe(403);
      expect((await handleTransitionRequest(post(obs.id,"validate","Ratifico la revisión de evidencia."),{DB:f.db},"eva","c_a",obs.id)).status).toBe(409);
      expect((await handleTransitionRequest(post(obs.id,"submit",undefined,{key:"x"}),{DB:f.db},"alice","c_a",obs.id)).status).toBe(400);
      const forged=new Request(`${base}/observations/${obs.id}/actions`,{method:"POST",
        headers:{"Content-Type":"application/json","Idempotency-Key":"valid_key_12345"},
        body:JSON.stringify({action:"submit",actor:"eva"})});
      expect((await handleTransitionRequest(forged,{DB:f.db},"alice","c_a",obs.id)).status).toBe(400);
    } finally {f.close();}
  });
});
