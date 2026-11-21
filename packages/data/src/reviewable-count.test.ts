import { describe, expect, it } from "vitest";
import { makeD1 } from "../../../tests/helpers/d1";
import { countReviewableObservations } from "./reviewable-count";

function fixture() {
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('c_a','Synthetic A','active'),
      ('c_b','Synthetic B','active'),
      ('c_closed','Synthetic C','closed');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('c_a','author','member',1),
      ('c_a','reviewer','president',1),
      ('c_a','reader','observer',1),
      ('c_a','advisor','advisor',1),
      ('c_a','revoked','member',0),
      ('c_b','author','member',1),
      ('c_b','reviewer','president',1),
      ('c_closed','author','member',1),
      ('c_closed','reviewer','president',1);
    INSERT INTO document_batches(id,commission_id,label)
      VALUES('batch_a','c_a','Synthetic'),('batch_b','c_b','Synthetic');
    INSERT INTO checklist_items(id,commission_id,area,expected_document)
      VALUES('item_a','c_a','works','Synthetic'),('item_b','c_b','works','Synthetic');
  `);
  const observation=f.sqlite.prepare(`
    INSERT INTO observations(id,commission_id,author_subject,title,description)
      VALUES(?,?,?,'Synthetic finding','Synthetic evidence')
  `);
  const evidence=f.sqlite.prepare(`
    INSERT INTO observation_evidence(id,observation_id,type,reference_json)
      VALUES(?,?,'SEARCH_SCOPE',?)
  `);
  const submit=f.sqlite.prepare(`
    UPDATE observations SET status='in_review',submitted_by=author_subject,
      submitted_at=CURRENT_TIMESTAMP,submit_request_key=? WHERE id=?
  `);
  for(let i=0;i<31;i++) {
    const id="other_"+i;
    observation.run(id,"c_a","author");
    evidence.run("e_"+id,id,JSON.stringify({
      type:"SEARCH_SCOPE",commissionId:"c_a",checklistItemId:"item_a",
      batchId:"batch_a",reviewerId:"author",searchedAt:"2026-11-20T12:00:00.000Z"
    }));
    submit.run("submit_"+id,id);
  }
  for(let i=0;i<4;i++) {
    const id="own_"+i;
    observation.run(id,"c_a","reviewer");
    evidence.run("e_"+id,id,JSON.stringify({
      type:"SEARCH_SCOPE",commissionId:"c_a",checklistItemId:"item_a",
      batchId:"batch_a",reviewerId:"reviewer",searchedAt:"2026-11-20T12:00:00.000Z"
    }));
    submit.run("submit_"+id,id);
  }
  for(let i=0;i<7;i++) {
    const id="b_"+i;
    observation.run(id,"c_b","author");
    evidence.run("e_"+id,id,JSON.stringify({
      type:"SEARCH_SCOPE",commissionId:"c_b",checklistItemId:"item_b",
      batchId:"batch_b",reviewerId:"author",searchedAt:"2026-11-20T12:00:00.000Z"
    }));
    submit.run("submit_"+id,id);
  }
  f.sqlite.exec(`
    INSERT INTO observations(id,commission_id,author_subject,title,description)
      VALUES('draft','c_a','author','Draft','Not yet submitted');
    UPDATE observations SET status='validated',reviewed_by='reviewer',
      reviewed_at=CURRENT_TIMESTAMP,review_note='Synthetic independent review note',
      validated_by='reviewer',validated_at=CURRENT_TIMESTAMP,
      review_request_key='decision_other_0' WHERE id='other_0';
  `);
  return f;
}

describe("commission-scoped reviewable count with D1 index",()=>{
  it("counts the complete queue, not 25 history rows, excluding own drafts and decisions",async()=>{
    const f=fixture();
    try {
      expect(await countReviewableObservations(f.db,"reviewer","c_a")).toBe(30);
      expect(await countReviewableObservations(f.db,"reviewer","c_b")).toBe(7);
      expect(await countReviewableObservations(f.db,"author","c_a")).toBe(4);
    }finally{f.close();}
  });

  it("returns zero for observer/advisor/inactive/unknown without cross-tenant leakage",async()=>{
    const f=fixture();
    try {
      for(const subject of ["reader","advisor","revoked","missing"]) {
        expect(await countReviewableObservations(f.db,subject,"c_a")).toBe(0);
      }
      expect(await countReviewableObservations(f.db,"reviewer","c_closed")).toBe(0);
      f.sqlite.exec("UPDATE commission_members SET role='observer' WHERE commission_id='c_a' AND subject='reviewer'");
      expect(await countReviewableObservations(f.db,"reviewer","c_a")).toBe(0);
    }finally{f.close();}
  });

  it("counts without mutating audit and uses commission/status index rather than full history",async()=>{
    const f=fixture();
    try {
      const before=f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get();
      await countReviewableObservations(f.db,"reviewer","c_a");
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toEqual(before);
      const plan=f.sqlite.prepare(`
        EXPLAIN QUERY PLAN SELECT COUNT(*) FROM observations
        WHERE commission_id='c_a' AND status='in_review' AND author_subject<>'reviewer'
      `).all() as Array<{detail:string}>;
      expect(plan.some(row=>row.detail.includes("idx_observations_commission"))).toBe(true);
      expect(plan.some(row=>row.detail.includes("USE TEMP B-TREE"))).toBe(false);
    }finally{f.close();}
  });
});
