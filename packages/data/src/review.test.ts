import { describe, expect, it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { listChecklist, listObservationDrafts, persistDraftObservation } from "./review";

function fixture() {
  const f = makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('c_a','Comisión A','active'),('c_b','Comisión B','active'),('c_closed','Archivada','closed');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('c_a','alice','member',1), ('c_a','advisor','advisor',1),
      ('c_a','observer','observer',1), ('c_a','revoked','president',0),
      ('c_b','bob','member',1), ('c_closed','alice','president',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES
      ('b_a','c_a','Obras'),('b_b','c_b','Otro lote'),('b_closed','c_closed','Archivo');
    INSERT INTO checklist_items(id,commission_id,area,expected_document) VALUES
      ('item_a','c_a','works','Expediente de obra'),
      ('item_b','c_b','procurement','Contrato B'),
      ('item_closed','c_closed','works','Obra cerrada');
  `);
  return f;
}
const input = {
  commissionId: "c_a", authorSubject: "alice", title: "Expediente no ubicado",
  description: "La búsqueda manual del lote no encontró el expediente esperado.",
  evidence: [{
    type: "SEARCH_SCOPE" as const, commissionId:"c_a", checklistItemId:"item_a",
    batchId:"b_a", reviewerId:"alice", searchedAt:"2026-11-18T16:00:00.000Z"
  }]
};

describe("review storage with tenant-scoped provenance", () => {
  it("lists checklist rows only for active members of the commission", async () => {
    const f=fixture();
    try {
      expect(await listChecklist(f.db,"alice","c_a")).toMatchObject([{id:"item_a",status:"pending"}]);
      expect(await listChecklist(f.db,"alice","c_b")).toEqual([]);
      expect(await listChecklist(f.db,"revoked","c_a")).toEqual([]);
      expect(await listChecklist(f.db,"bob","c_b")).toMatchObject([{id:"item_b"}]);
    } finally {f.close();}
  });

  it("saves a human observation, one scoped evidence and an audit event atomically", async () => {
    const f=fixture();
    try {
      const result=await persistDraftObservation(f.db,input);
      expect(result.status).toBe("draft");
      expect(result.evidence).toEqual(input.evidence);
      const rows=await listObservationDrafts(f.db,"alice","c_a");
      expect(rows).toMatchObject([{id:result.id,status:"draft",validatedBy:null}]);
      expect(rows[0]?.evidence).toEqual(input.evidence);
      expect(f.sqlite.prepare("SELECT COUNT(*) AS count FROM audit_events").get()).toMatchObject({count:1});
      expect(f.sqlite.prepare("SELECT status, reviewed_by FROM checklist_items WHERE id='item_a'").get())
        .toMatchObject({status:"pending",reviewed_by:null});
    } finally {f.close();}
  });

  it("refuses anonymous, observer, revoked and cross-commission writes", async () => {
    const f=fixture();
    try {
      for (const authorSubject of ["observer","revoked","nobody"]) {
        await expect(persistDraftObservation(f.db,{...input,authorSubject,
          evidence:[{...input.evidence[0]!,reviewerId:authorSubject}]})).rejects.toThrow();
      }
      await expect(persistDraftObservation(f.db,{...input,evidence:[{...input.evidence[0]!,batchId:"b_b"}]})).rejects.toThrow();
      await expect(persistDraftObservation(f.db,{...input,evidence:[{...input.evidence[0]!,checklistItemId:"item_b"}]})).rejects.toThrow();
      expect(f.sqlite.prepare("SELECT COUNT(*) AS count FROM observations").get()).toMatchObject({count:0});
    } finally {f.close();}
  });

  it("refuses a missing-document search against checklist items already located", async () => {
    const f=fixture();
    try {
      f.sqlite.exec("UPDATE checklist_items SET status='located' WHERE id='item_a'");
      await expect(persistDraftObservation(f.db,input)).rejects.toThrow();
      expect(f.sqlite.prepare("SELECT COUNT(*) AS count FROM observations").get()).toMatchObject({count:0});
    } finally {f.close();}
  });

  it("refuses forged reviewers, unsupported official references and quarantined page citations", async () => {
    const f=fixture();
    try {
      await expect(persistDraftObservation(f.db,{...input,evidence:[{...input.evidence[0]!,reviewerId:"bob"}]})).rejects.toThrow();
      await expect(persistDraftObservation(f.db,{...input,evidence:[{
        type:"OFFICIAL_SOURCE",commissionId:"c_a",source:"Portal",
        sourceRecordId:"register-1",consultedAt:"2026-11-18T16:00:00.000Z",cutOffAt:"2026-11-18"
      }]})).rejects.toThrow();
      f.sqlite.exec(`
        INSERT INTO documents(id,commission_id,batch_id,filename) VALUES('doc_a','c_a','b_a','test.pdf');
        INSERT INTO document_versions(id,document_id,version_number,sha256,r2_object_key,page_count)
          VALUES('ver_a','doc_a',1,'${"a".repeat(64)}','quarantine/test.pdf',3);
      `);
      await expect(persistDraftObservation(f.db,{...input,evidence:[{
        type:"DOCUMENT_PAGE",commissionId:"c_a",documentVersionId:"ver_a",
        page:1,sha256:"a".repeat(64)
      }]})).rejects.toThrow();
    } finally {f.close();}
  });

  it("accepts page evidence only if its extracted page and version are ready with matching hash", async () => {
    const f=fixture();
    try {
      f.sqlite.exec(`
        INSERT INTO documents(id,commission_id,batch_id,filename) VALUES('doc_a','c_a','b_a','test.pdf');
        INSERT INTO document_versions(id,document_id,version_number,sha256,r2_object_key,page_count,extraction_status)
          VALUES('ver_a','doc_a',1,'${"a".repeat(64)}','processed/test.pdf',3,'ready');
        INSERT INTO document_pages(document_version_id,page,extracted_text,extraction_status)
          VALUES('ver_a',2,'Texto ya procesado','ready');
      `);
      const proof={type:"DOCUMENT_PAGE" as const,commissionId:"c_a",documentVersionId:"ver_a",
        page:2,sha256:"a".repeat(64)};
      const result=await persistDraftObservation(f.db,{...input,evidence:[proof]});
      expect(result.evidence).toEqual([proof]);
      await expect(persistDraftObservation(f.db,{...input,evidence:[{...proof,page:9}]})).rejects.toThrow();
      await expect(persistDraftObservation(f.db,{...input,evidence:[{...proof,sha256:"b".repeat(64)}]})).rejects.toThrow();
    } finally {f.close();}
  });

  it("refuses writing to closed commissions and does not expose other subjects' observations", async () => {
    const f=fixture();
    try {
      await expect(persistDraftObservation(f.db,{...input,commissionId:"c_closed",
        evidence:[{...input.evidence[0]!,commissionId:"c_closed",checklistItemId:"item_closed",batchId:"b_closed"}]
      })).rejects.toThrow();
      await persistDraftObservation(f.db,input);
      expect(await listObservationDrafts(f.db,"bob","c_a")).toEqual([]);
      expect(await listObservationDrafts(f.db,"alice","c_b")).toEqual([]);
    } finally {f.close();}
  });
});
