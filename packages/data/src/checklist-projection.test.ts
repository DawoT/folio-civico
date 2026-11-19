import { describe, expect, it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { listChecklist, persistDraftObservation, transitionObservation } from "./index";

function fixture() {
  const f = makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES ('commission_a','A','active'),('commission_b','B','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('commission_a','author','member',1),
      ('commission_a','reviewer','president',1),
      ('commission_a','observer','observer',1),
      ('commission_a','revoked','member',0),
      ('commission_b','outside','president',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES
      ('batch_a','commission_a','Expedientes A'),('batch_b','commission_b','Expedientes B');
    INSERT INTO checklist_items(id,commission_id,area,expected_document) VALUES
      ('expected_a','commission_a','works','Expediente de obra A'),
      ('expected_a2','commission_a','works','Expediente de obra A2'),
      ('expected_b','commission_b','procurement','Contrato B');
  `);
  return f;
}

async function draft(db: D1Database, itemId = "expected_a") {
  return persistDraftObservation(db, {
    commissionId: "commission_a", authorSubject: "author",
    title: "No se ubicó el expediente", description: "Se revisó el lote asignado y no se encontró.",
    evidence: [{ type: "SEARCH_SCOPE", commissionId: "commission_a",
      checklistItemId: itemId, batchId: "batch_a", reviewerId: "author",
      searchedAt: "2026-11-18T14:00:00.000Z" }]
  });
}

async function decide(db: D1Database, observationId: string, action: "validate" | "dismiss") {
  await transitionObservation(db, {
    commissionId: "commission_a", subject: "author", observationId,
    action: "submit", requestKey: "submit_req_12345"
  });
  return transitionObservation(db, {
    commissionId: "commission_a", subject: "reviewer", observationId,
    action, note: "Verifiqué la búsqueda descrita y los registros del lote.",
    requestKey: "decision_req_12345"
  });
}

describe("validated-search checklist projection", () => {
  it("does not convert drafts, submissions or dismissed observations into a confirmed absence", async () => {
    const f = fixture();
    try {
      const record = await draft(f.db);
      const initial = await listChecklist(f.db, "author", "commission_a");
      expect(initial.find(row => row.id === "expected_a")).toMatchObject({
        status: "pending", statusSource: "stored", validatedSearchObservationId: null
      });
      await transitionObservation(f.db, {
        commissionId: "commission_a", subject: "author", observationId: record.id,
        action: "submit", requestKey: "submit_req_12345"
      });
      expect((await listChecklist(f.db, "author", "commission_a"))
        .find(row => row.id === "expected_a")?.status).toBe("pending");
      await transitionObservation(f.db, {
        commissionId: "commission_a", subject: "reviewer", observationId: record.id,
        action: "dismiss", note: "El alcance de búsqueda no acredita la ausencia.",
        requestKey: "decision_req_12345"
      });
      expect((await listChecklist(f.db, "author", "commission_a"))
        .find(row => row.id === "expected_a")?.status).toBe("pending");
    } finally { f.close(); }
  });

  it("reflects a distinct human validation with reviewer and exact observation provenance", async () => {
    const f = fixture();
    try {
      const record = await draft(f.db);
      await decide(f.db, record.id, "validate");
      const rows = await listChecklist(f.db, "author", "commission_a");
      expect(rows.find(row => row.id === "expected_a")).toMatchObject({
        status: "not_located", statusSource: "validated_search",
        validatedSearchObservationId: record.id, reviewedBy: "reviewer"
      });
      expect(rows.find(row => row.id === "expected_a")?.reviewedAt).toBeTruthy();
      expect(rows.find(row => row.id === "expected_a2")).toMatchObject({
        status: "pending", statusSource: "stored", validatedSearchObservationId: null
      });
      // Derived from immutable review evidence; no direct mutation of the official checklist row.
      expect(f.sqlite.prepare("SELECT status,reviewed_by FROM checklist_items WHERE id='expected_a'").get())
        .toMatchObject({ status: "pending", reviewed_by: null });
    } finally { f.close(); }
  });

  it("never leaks evidence across commission boundaries or overrides independently located items", async () => {
    const f = fixture();
    try {
      const record = await draft(f.db);
      await decide(f.db, record.id, "validate");
      expect(await listChecklist(f.db, "outside", "commission_a")).toEqual([]);
      expect(await listChecklist(f.db, "revoked", "commission_a")).toEqual([]);
      expect(await listChecklist(f.db, "outside", "commission_b")).toMatchObject([
        { id: "expected_b", status: "pending", validatedSearchObservationId: null }
      ]);
      f.sqlite.exec("UPDATE checklist_items SET status='located' WHERE id='expected_a'");
      expect((await listChecklist(f.db, "observer", "commission_a"))
        .find(row => row.id === "expected_a")).toMatchObject({
          status: "located", statusSource: "stored", validatedSearchObservationId: null
        });
    } finally { f.close(); }
  });
});
