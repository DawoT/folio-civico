import {describe,expect,it} from "vitest";
import {makeD1} from "../../../tests/helpers/d1";

const actor="synthetic_case_actor";
const source="a".repeat(64);
const id="00000000-0000-4000-8000-000000000030";
function pendingCase(d:ReturnType<typeof makeD1>,gate=1,idValue=id) {
  d.sqlite.prepare(`
    INSERT INTO processing_async_revocation_requests(
      id,actor_subject,request_key,kind,target,incident_ref,
      target_sha256,reason_sha256,payload_sha256,expires_at,
      institutional_gate_required
    ) VALUES(?,?,'revoke_case_journal_003','image',?,
      'INC_TEST_INVALIDATION_01',?,?,?,unixepoch()+300,?)
  `).run(idValue,actor,"sha256:"+"c".repeat(64),source,source,source,gate);
}
function invalidate(d:ReturnType<typeof makeD1>,requestId=id,purpose="revocation"){
  return d.sqlite.prepare(`
    INSERT INTO processing_institutional_approval_invalidations(
      purpose,request_id,case_revision,reason,evidence_sha256
    ) VALUES(?,?,8,'case_closed',?)
  `).run(purpose,requestId,"d".repeat(64));
}
describe("R2.12b/P3 synthetic D1 institutional invalidation",()=>{
  it("records one immutable, scoped invalidation and disallows deletion/rewrite",()=>{
    const d=makeD1();
    try{
      pendingCase(d);
      invalidate(d);
      expect(d.sqlite.prepare(`
        SELECT purpose,request_id AS requestId,case_revision AS revision,reason
        FROM processing_institutional_approval_invalidations
      `).get()).toMatchObject({
        purpose:"revocation",requestId:id,revision:8,reason:"case_closed"
      });
      expect(()=>invalidate(d)).toThrow();
      expect(()=>d.sqlite.exec(
        "UPDATE processing_institutional_approval_invalidations SET reason='case_superseded'"
      )).toThrow(/INSTITUTIONAL_INVALIDATION_IMMUTABLE/);
      expect(()=>d.sqlite.exec(
        "DELETE FROM processing_institutional_approval_invalidations"
      )).toThrow(/INSTITUTIONAL_INVALIDATION_IMMUTABLE/);
    }finally{d.close();}
  });
  it("rejects invalidation for a nonexistent or ungated request",()=>{
    const d=makeD1();
    try{
      expect(()=>invalidate(d)).toThrow(/INSTITUTIONAL_INVALIDATION_INVALID/);
      pendingCase(d,0);
      expect(()=>invalidate(d)).toThrow(/INSTITUTIONAL_INVALIDATION_INVALID/);
      expect(d.sqlite.prepare(
        "SELECT count(*) AS n FROM processing_institutional_approval_invalidations"
      ).get()).toMatchObject({n:0});
    }finally{d.close();}
  });
});
