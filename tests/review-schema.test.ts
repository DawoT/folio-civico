import { describe, expect, it } from "vitest";
import { makeD1 } from "./helpers/d1";

describe("D1 evidence provenance triggers", () => {
  function fixture() {
    const f=makeD1();
    f.sqlite.exec(`
      INSERT INTO commissions(id,name) VALUES ('c_a','A'),('c_b','B');
      INSERT INTO commission_members(commission_id,subject,role,active)
        VALUES ('c_a','alice','member',1),('c_b','bob','member',1);
      INSERT INTO checklist_items(id,commission_id,area,expected_document)
        VALUES ('item_a','c_a','works','Contrato A'),('item_b','c_b','works','Contrato B');
      INSERT INTO document_batches(id,commission_id,label)
        VALUES('b_a','c_a','Archivo A'),('b_b','c_b','Archivo B');
      INSERT INTO observations(id,commission_id,author_subject,title,description)
        VALUES('obs_a','c_a','alice','Faltante','Búsqueda documentada');
    `);
    return f;
  }
  function proof(commissionId="c_a",checklistItemId="item_a",batchId="b_a") {
    return JSON.stringify({
      type:"SEARCH_SCOPE",commissionId,checklistItemId,batchId,
      reviewerId:"alice",searchedAt:"2026-11-18T12:00:00.000Z"
    });
  }
  it("rejects commission, checklist and batch mismatches in direct SQL writes", () => {
    const f=fixture();
    try {
      const insert=f.sqlite.prepare("INSERT INTO observation_evidence(id,observation_id,type,reference_json) VALUES(?,?,?,?)");
      expect(()=>insert.run("ev_1","obs_a","SEARCH_SCOPE",proof("c_b","item_b","b_b"))).toThrow();
      expect(()=>insert.run("ev_2","obs_a","SEARCH_SCOPE",proof("c_a","item_b","b_a"))).toThrow();
      expect(()=>insert.run("ev_3","obs_a","SEARCH_SCOPE",proof("c_a","item_a","b_b"))).toThrow();
      const invalidDate=JSON.stringify({...JSON.parse(proof()),searchedAt:"yesterday"});
      expect(()=>insert.run("ev_4","obs_a","SEARCH_SCOPE",invalidDate)).toThrow();
      expect(f.sqlite.prepare("SELECT COUNT(*) AS count FROM observation_evidence").get()).toMatchObject({count:0});
    } finally {f.close();}
  });

  it("permits only valid search scope and makes its evidence immutable", () => {
    const f=fixture();
    try {
      f.sqlite.prepare("INSERT INTO observation_evidence(id,observation_id,type,reference_json) VALUES(?,?,?,?)")
        .run("ev_1","obs_a","SEARCH_SCOPE",proof());
      expect(()=>f.sqlite.exec("DELETE FROM observation_evidence WHERE id='ev_1'")).toThrow(/EVIDENCE_IMMUTABLE/);
      expect(()=>f.sqlite.exec("UPDATE observation_evidence SET type='OFFICIAL_SOURCE' WHERE id='ev_1'")).toThrow(/EVIDENCE_IMMUTABLE/);
    } finally {f.close();}
  });
});
