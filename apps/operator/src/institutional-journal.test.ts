import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";

function proposal(d:ReturnType<typeof makeD1>,id:string){
  const h="a".repeat(64);
  d.sqlite.prepare(`
    INSERT INTO processing_async_revocation_requests(
      id,actor_subject,request_key,kind,target,incident_ref,
      target_sha256,reason_sha256,payload_sha256,expires_at,institutional_gate_required
    ) VALUES(?,'synthetic_actor',?,'image',?,
      'INC_JOURNAL_SYNTHETIC',?,?,?,unixepoch()+300,1)
  `).run(id,`request_journal_${id.slice(-3)}`,"sha256:"+"c".repeat(64),h,h,h);
}
describe("R2.12b/P2 durable institutional approval receipts",()=>{
  it("rejects stale or unbound SQL evidence and leaves the protected proposal pending",()=>{
    const d=makeD1();
    try{
      const id="00000000-0000-4000-8000-000000000012";
      proposal(d,id);
      const insert=(actor:string,checkedAt:number)=>d.sqlite.prepare(`
        INSERT INTO processing_institutional_approval_evidence(
          purpose,request_id,actor_subject,approver_subject,scope_sha256,
          approval_sha256,case_revision,checked_at,expires_at
        ) SELECT 'revocation',id,?,?,?,?,?, ?,expires_at
          FROM processing_async_revocation_requests WHERE id=?
      `).run(actor,"synthetic_reviewer","a".repeat(64),"b".repeat(64),
        7,checkedAt,id);
      expect(()=>insert("wrong_actor",Math.floor(Date.now()/1000)))
        .toThrow(/INSTITUTIONAL_EVIDENCE_INVALID/);
      expect(()=>insert("synthetic_actor",Math.floor(Date.now()/1000)-60))
        .toThrow(/INSTITUTIONAL_EVIDENCE_INVALID/);
      expect(d.sqlite.prepare("SELECT count(*) AS n FROM processing_institutional_approval_evidence").get())
        .toMatchObject({n:0});
      expect(d.sqlite.prepare("SELECT status FROM processing_async_revocation_requests WHERE id=?").get(id))
        .toMatchObject({status:"pending"});
    }finally{d.close();}
  });


  it("denies downgrading a protected proposal and SQL approval without evidence",()=>{
    const d=makeD1();
    try{
      const id="00000000-0000-4000-8000-000000000010";
      proposal(d,id);
      expect(()=>d.sqlite.prepare(`
        UPDATE processing_async_revocation_requests
        SET institutional_gate_required=0 WHERE id=?
      `).run(id)).toThrow(/INSTITUTIONAL_GATE_IMMUTABLE/);
      expect(()=>d.sqlite.prepare(`
        UPDATE processing_async_revocation_requests
        SET status='approved',approver_subject=?,approval_sha256=?,
          approval_key_thumbprint=?,decided_at=unixepoch() WHERE id=?
      `).run("synthetic_reviewer","b".repeat(64),"A".repeat(43),id))
        .toThrow(/INSTITUTIONAL_EVIDENCE_REQUIRED/);
    }finally{d.close();}
  });
  it("stores exact scoped metadata, immutable and without JWTs or case contents",()=>{
    const d=makeD1();
    try{
      const id="00000000-0000-4000-8000-000000000011";
      proposal(d,id);
      d.sqlite.prepare(`
        INSERT INTO processing_institutional_approval_evidence(
          purpose,request_id,actor_subject,approver_subject,scope_sha256,
          approval_sha256,case_revision,checked_at,expires_at
        ) SELECT 'revocation',id,actor_subject,?,?,?,?,unixepoch(),
          expires_at FROM processing_async_revocation_requests WHERE id=?
      `).run("synthetic_reviewer","a".repeat(64),"b".repeat(64),7,id);
      expect(()=>d.sqlite.prepare(`
        UPDATE processing_institutional_approval_evidence SET case_revision=8
      `).run()).toThrow(/INSTITUTIONAL_EVIDENCE_IMMUTABLE/);
      expect(()=>d.sqlite.exec(`
        DELETE FROM processing_institutional_approval_evidence
      `)).toThrow(/INSTITUTIONAL_EVIDENCE_IMMUTABLE/);
      expect(()=>d.sqlite.prepare(`
        INSERT INTO processing_institutional_approval_evidence(
          purpose,request_id,actor_subject,approver_subject,scope_sha256,
          approval_sha256,case_revision,checked_at,expires_at
        ) VALUES('revocation',?,?,?,?,?,?,unixepoch(),unixepoch()+300)
      `).run(id,"synthetic_actor","synthetic_reviewer","a".repeat(64),
        "b".repeat(64),8)).toThrow();
    }finally{d.close();}
  });
});
