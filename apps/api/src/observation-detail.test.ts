import { describe, expect, it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { persistDraftObservation, transitionObservation } from "@folio/data";
import { handleObservationDetailRequest } from "./observation-detail";

function fixture() {
  const f = makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES('c_a','A','active'),('c_b','B','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('c_a','alice','member',1),('c_a','eva','president',1),
      ('c_a','reader','observer',1),('c_a','revoked','member',0),
      ('c_b','bob','member',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES('b_a','c_a','Expedientes');
    INSERT INTO checklist_items(id,commission_id,area,expected_document)
      VALUES('item_a','c_a','works','Informe de obra');
  `);
  return f;
}

async function createValidated(db: D1Database) {
  const item = await persistDraftObservation(db, {
    commissionId:"c_a", authorSubject:"alice", title:"Expediente no ubicado",
    description:"Revisé el lote y no se encontró el documento.",
    evidence:[{ type:"SEARCH_SCOPE", commissionId:"c_a", checklistItemId:"item_a",
      batchId:"b_a", reviewerId:"alice", searchedAt:"2026-11-18T13:00:00.000Z" }]
  });
  await transitionObservation(db,{
    commissionId:"c_a",observationId:item.id,subject:"alice",action:"submit",requestKey:"submit_req_12345"
  });
  await transitionObservation(db,{
    commissionId:"c_a",observationId:item.id,subject:"eva",action:"validate",
    note:"Verifiqué el alcance de esta búsqueda documental.",requestKey:"validate_req_12345"
  });
  return item;
}

const url = (id:string) => `https://folio.test/api/commissions/c_a/observations/${id}`;

describe("authorized single-observation detail", () => {
  it("returns the exact validated decision, evidence and reviewer, but never idempotency secrets", async () => {
    const f=fixture();
    try {
      const record=await createValidated(f.db);
      const response=await handleObservationDetailRequest(new Request(url(record.id)),{DB:f.db},"reader","c_a",record.id);
      expect(response.status).toBe(200);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      const body=await response.json() as Record<string,unknown>;
      expect(body).toMatchObject({id:record.id,commissionId:"c_a",status:"validated",reviewedBy:"eva",
        evidence:[{type:"SEARCH_SCOPE",checklistItemId:"item_a",reviewerId:"alice"}]});
      for(const forbidden of ["submitRequestKey","reviewRequestKey","draftRequestKey","draftPayloadSha256"]) {
        expect(body).not.toHaveProperty(forbidden);
      }
    } finally {f.close();}
  });

  it("returns 404 for nonmembers, revoked identities, wrong commissions and unknown IDs", async () => {
    const f=fixture();
    try {
      const record=await createValidated(f.db);
      for(const who of ["bob","revoked","stranger"]) {
        expect((await handleObservationDetailRequest(new Request(url(record.id)),{DB:f.db},who,"c_a",record.id)).status).toBe(404);
      }
      expect((await handleObservationDetailRequest(new Request(url(record.id)),{DB:f.db},"bob","c_b",record.id)).status).toBe(404);
      expect((await handleObservationDetailRequest(new Request(url("not_found")),{DB:f.db},"reader","c_a","not_found")).status).toBe(404);
    } finally {f.close();}
  });

  it("does not accept mutation methods and does not modify observations or audit", async () => {
    const f=fixture();
    try {
      const record=await createValidated(f.db);
      const before=f.sqlite.prepare("SELECT count(*) AS count FROM audit_events").get();
      const response=await handleObservationDetailRequest(new Request(url(record.id),{method:"POST"}),
        {DB:f.db},"eva","c_a",record.id);
      expect(response.status).toBe(405);
      expect(f.sqlite.prepare("SELECT count(*) AS count FROM audit_events").get()).toEqual(before);
    } finally {f.close();}
  });
});
