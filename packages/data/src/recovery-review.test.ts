import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";
import {persistDocumentUpload} from "./documents";
import {
  openRecoveryReview,decideRecoveryReview,
  RecoveryReviewAccessError,RecoveryReviewConflictError,RecoveryReviewInputError
} from "./recovery-review";

const SHA="a".repeat(64);
async function fixture(){
  const f=makeD1();
  f.sqlite.exec(`
    INSERT INTO commissions(id,name,status) VALUES
      ('c_a','Comisión A','active'),('c_b','Comisión B','active');
    INSERT INTO commission_members(commission_id,subject,role,active) VALUES
      ('c_a','president','president',1),
      ('c_a','reviewer','member',1),
      ('c_a','observer','observer',1),
      ('c_a','advisor','advisor',1),
      ('c_a','revoked','member',0),
      ('c_b','outsider','president',1);
    INSERT INTO document_batches(id,commission_id,label) VALUES
      ('batch_a','c_a','Lote A'),('batch_b','c_b','Lote B');
  `);
  const upload=async(versionId:string,commissionId="c_a")=>persistDocumentUpload(f.db,{
    commissionId,batchId:commissionId==="c_a"?"batch_a":"batch_b",
    subject:commissionId==="c_a"?"president":"outsider",
    documentId:"doc_"+versionId,versionId,
    sha256:SHA,r2Key:"quarantine/"+versionId+".pdf",
    filename:"Fixture.pdf",idempotencyKey:"upload_"+versionId+"_unique"
  });
  await upload("version_a");
  await upload("version_b");
  await upload("version_other","c_b");
  const exhaust=(id:string)=>f.sqlite.prepare(`
    UPDATE document_processing_outbox
    SET state='sent',attempts=10,last_sent_at='2026-11-19T12:00:00.000Z'
    WHERE document_version_id=?
  `).run(id);
  exhaust("version_a");
  exhaust("version_other");
  return {...f,exhaust};
}
const open=(overrides:Record<string,unknown>={})=>({
  commissionId:"c_a",versionId:"version_a",sourceSha256:SHA,
  actorSubject:"president",incidentRef:"INC_20261119_001",
  requestKey:"recovery_open_0001",...overrides
});
const decide=(id:string,overrides:Record<string,unknown>={})=>({
  commissionId:"c_a",reviewId:id,actorSubject:"reviewer",
  requestKey:"recovery_decide_001",decision:"endorse" as const,
  rationale:"Segundo análisis del incidente, únicamente para evaluación del operador.",
  ...overrides
});

describe("R2.4 · two-person recovery review without redrive",()=>{
  it("requires exhausted outbox and an active president, journals open and independent endorsement exactly once",async()=>{
    const f=await fixture();
    try{
      const before=f.sqlite.prepare("SELECT state,attempts,last_sent_at AS lastSentAt FROM document_processing_outbox WHERE document_version_id='version_a'").get();
      const first=await openRecoveryReview(f.db,open());
      expect(first).toMatchObject({status:"in_review",replayed:false});
      expect(first.id).toMatch(/^[0-9a-f-]{36}$/);
      const replay=await openRecoveryReview(f.db,open());
      expect(replay).toEqual({...first,replayed:true});
      const endorsed=await decideRecoveryReview(f.db,decide(first.id));
      expect(endorsed).toEqual({id:first.id,status:"endorsed_for_operator_review",replayed:false});
      expect(await decideRecoveryReview(f.db,decide(first.id)))
        .toEqual({...endorsed,replayed:true});
      expect(f.sqlite.prepare("SELECT status,requested_by AS requestedBy,reviewed_by AS reviewedBy FROM processing_recovery_reviews").get())
        .toMatchObject({status:"endorsed_for_operator_review",requestedBy:"president",reviewedBy:"reviewer"});
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_recovery_actions").get()).toMatchObject({n:2});
      expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get()).toMatchObject({n:5});
      expect(f.sqlite.prepare("SELECT state,attempts,last_sent_at AS lastSentAt FROM document_processing_outbox WHERE document_version_id='version_a'").get())
        .toEqual(before);
      const serialized=JSON.stringify(f.sqlite.prepare("SELECT * FROM processing_recovery_reviews").all());
      expect(serialized).not.toContain("Segundo análisis del incidente");
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM document_processing_reports").get()).toMatchObject({n:0});
    }finally{f.close();}
  });

  it("refuses self endorsement, lower roles, revoked and cross-tenant actors; does not leak cases",async()=>{
    const f=await fixture();
    try{
      const record=await openRecoveryReview(f.db,open());
      for(const actorSubject of ["president","observer","advisor","revoked","outsider","nobody"]){
        await expect(decideRecoveryReview(f.db,decide(record.id,{
          actorSubject,requestKey:"review_"+actorSubject+"_0001"
        }))).rejects.toBeInstanceOf(RecoveryReviewAccessError);
      }
      for(const actorSubject of ["reviewer","observer","advisor","revoked","outsider","nobody"]){
        await expect(openRecoveryReview(f.db,open({
          actorSubject,requestKey:"open_"+actorSubject+"_0002"
        }))).rejects.toBeInstanceOf(RecoveryReviewAccessError);
      }
      await expect(decideRecoveryReview(f.db,decide(record.id,{
        commissionId:"c_b",actorSubject:"outsider",requestKey:"outsider_decide_01"
      }))).rejects.toBeInstanceOf(RecoveryReviewAccessError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM processing_recovery_actions").get()).toMatchObject({n:1});
    }finally{f.close();}
  });

  it("denies nonexhausted, completed, rejected and closed cases and refuses stale endorsements",async()=>{
    const f=await fixture();
    try{
      await expect(openRecoveryReview(f.db,open({
        versionId:"version_b",requestKey:"not_exhausted_001"
      }))).rejects.toBeInstanceOf(RecoveryReviewConflictError);
      const record=await openRecoveryReview(f.db,open());
      f.sqlite.exec("UPDATE document_versions SET extraction_status='needs_review' WHERE id='version_a'");
      await expect(decideRecoveryReview(f.db,decide(record.id)))
        .rejects.toBeInstanceOf(RecoveryReviewConflictError);
      const dismissed=await decideRecoveryReview(f.db,decide(record.id,{
        decision:"dismiss",requestKey:"dismiss_record_001"
      }));
      expect(dismissed.status).toBe("dismissed");
      await expect(decideRecoveryReview(f.db,decide(record.id,{
        requestKey:"late_review_001"
      }))).rejects.toBeInstanceOf(RecoveryReviewConflictError);
      await expect(openRecoveryReview(f.db,open({
        requestKey:"second_open_001"
      }))).rejects.toBeInstanceOf(RecoveryReviewConflictError);
      f.sqlite.exec("UPDATE commissions SET status='closed' WHERE id='c_a'");
      await expect(openRecoveryReview(f.db,open({
        versionId:"version_a",requestKey:"closed_comm_001"
      }))).rejects.toBeInstanceOf(RecoveryReviewConflictError);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM audit_events").get()).toMatchObject({n:5});
    }finally{f.close();}
  });

  it("cannot circumvent DB permission or outbox exhaustion through raw inserts",async()=>{
    const f=await fixture();
    try{
      await expect(openRecoveryReview(f.db,open({
        sourceSha256:"b".repeat(64),requestKey:"source_mismatch_001"
      }))).rejects.toBeInstanceOf(RecoveryReviewConflictError);
      const before=f.sqlite.prepare("SELECT count(*) AS n FROM processing_recovery_reviews").get();
      expect(()=>f.sqlite.exec(`
        INSERT INTO processing_recovery_reviews(
          id,commission_id,document_version_id,source_sha256,incident_ref,requested_by
        ) VALUES('forged_case_01','c_a','version_b','${SHA}','INC_FORGED_2026','president')
      `)).toThrow(/RECOVERY_REVIEW_NOT_ELIGIBLE/);
      expect(()=>f.sqlite.exec(`
        INSERT INTO processing_recovery_reviews(
          id,commission_id,document_version_id,source_sha256,incident_ref,requested_by
        ) VALUES('forged_case_02','c_a','version_a','${SHA}','INC_FORGED_2026','observer')
      `)).toThrow(/RECOVERY_REVIEW_NOT_ELIGIBLE/);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM processing_recovery_reviews").get()).toEqual(before);
    }finally{f.close();}
  });

  it("blocks endorsement if membership, commission, or exhausted state changes while in review",async()=>{
    for(const mutation of [
      "UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='reviewer'",
      "UPDATE commissions SET status='closed' WHERE id='c_a'",
      "UPDATE document_processing_outbox SET attempts=9 WHERE document_version_id='version_a'",
      "UPDATE commission_members SET active=0 WHERE commission_id='c_a' AND subject='president'"
    ]){
      const f=await fixture();
      try{
        const record=await openRecoveryReview(f.db,open());
        f.sqlite.exec(mutation);
        await expect(decideRecoveryReview(f.db,decide(record.id)))
          .rejects.toBeInstanceOf(mutation.includes("subject='reviewer'")
            ?RecoveryReviewAccessError:RecoveryReviewConflictError);
        expect(f.sqlite.prepare("SELECT status FROM processing_recovery_reviews").get())
          .toMatchObject({status:"in_review"});
        expect(f.sqlite.prepare("SELECT COUNT(*) AS n FROM processing_recovery_actions").get())
          .toMatchObject({n:1});
      }finally{f.close();}
    }
  });

  it("rejects forged recovery journal actions across commission, actor, decision and state",async()=>{
    const f=await fixture();
    try{
      const review=await openRecoveryReview(f.db,open());
      for(const [commission,actor,action,status] of [
        ["c_b","outsider","open","in_review"],
        ["c_a","reviewer","open","in_review"],
        ["c_a","reviewer","endorse","endorsed_for_operator_review"],
        ["c_a","reviewer","dismiss","dismissed"]
      ] as const){
        expect(()=>f.sqlite.prepare(`
          INSERT INTO processing_recovery_actions(
            commission_id,actor_subject,request_key,review_id,action,payload_sha256,result_status
          ) VALUES(?,?,?,?,?,?,?)
        `).run(commission,actor,"fake_"+action+"_review_0001",
          review.id,action,SHA,status)).toThrow(/RECOVERY_ACTION_SCOPE_MISMATCH/);
      }
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM processing_recovery_actions").get())
        .toMatchObject({n:1});
    }finally{f.close();}
  });

  it("protects decisions and recovery records against update/delete including direct SQL",async()=>{
    const f=await fixture();
    try{
      const record=await openRecoveryReview(f.db,open());
      expect(()=>f.sqlite.exec("DELETE FROM processing_recovery_reviews"))
        .toThrow(/RECOVERY_REVIEW_IMMUTABLE/);
      expect(()=>f.sqlite.exec("UPDATE processing_recovery_reviews SET incident_ref='INC_FAKED_2026'"))
        .toThrow(/RECOVERY_REVIEW_IMMUTABLE/);
      expect(()=>f.sqlite.exec("UPDATE processing_recovery_reviews SET status='endorsed_for_operator_review'"))
        .toThrow(/RECOVERY_REVIEW_TRANSITION/);
      expect(()=>f.sqlite.exec("DELETE FROM processing_recovery_actions"))
        .toThrow(/RECOVERY_ACTION_IMMUTABLE/);
      expect(()=>f.sqlite.exec("UPDATE processing_recovery_actions SET request_key='faked_001'"))
        .toThrow(/RECOVERY_ACTION_IMMUTABLE/);
      expect(record.status).toBe("in_review");
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM processing_recovery_reviews").get()).toMatchObject({n:1});
    }finally{f.close();}
  });

  it("enforces strict input, request-key reuse, and no double-review race",async()=>{
    const f=await fixture();
    try{
      for(const overrides of [
        {sourceSha256:"not-a-hash",requestKey:"invalid_hash_0001"},
        {incidentRef:"../../secret",requestKey:"invalid_ticket_01"},
        {requestKey:"a"},
        {actorSubject:"user\nforged",requestKey:"invalid_actor_001"}
      ]){
        await expect(openRecoveryReview(f.db,open(overrides)))
          .rejects.toBeInstanceOf(RecoveryReviewInputError);
      }
      const record=await openRecoveryReview(f.db,open());
      await expect(openRecoveryReview(f.db,open({
        incidentRef:"INC_OTHER_0001"
      }))).rejects.toBeInstanceOf(RecoveryReviewConflictError);
      for(const overrides of [
        {rationale:"short",requestKey:"invalid_review_a"},
        {decision:"redrive",requestKey:"invalid_review_b"},
        {requestKey:"x"}
      ]){
        await expect(decideRecoveryReview(f.db,decide(record.id,overrides)))
          .rejects.toBeInstanceOf(RecoveryReviewInputError);
      }
      const outcomes=await Promise.allSettled([
        decideRecoveryReview(f.db,decide(record.id,{requestKey:"decision_parallel_a"})),
        decideRecoveryReview(f.db,decide(record.id,{
          requestKey:"decision_parallel_b",decision:"dismiss"
        }))
      ]);
      expect(outcomes.filter(x=>x.status==="fulfilled")).toHaveLength(1);
      expect(outcomes.filter(x=>x.status==="rejected")).toHaveLength(1);
      expect(f.sqlite.prepare("SELECT count(*) AS n FROM processing_recovery_actions").get()).toMatchObject({n:2});
    }finally{f.close();}
  });
});
