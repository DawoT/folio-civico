import {describe,expect,it,vi} from "vitest";
import {
  checkCurrentInstitutionalEvidence,
  InstitutionalEvidenceDenied,InstitutionalEvidenceUnavailable,
  type InstitutionalEvidenceQuery,type InstitutionalEvidenceSnapshot
} from "./institutional-authority";

const now=()=>Math.floor(Date.now()/1000);
const scope:InstitutionalEvidenceQuery={
  purpose:"revocation",caseRef:"INC_AUTHORIZED_123",requestId:"00000000-0000-4000-8000-000000000001",
  actorSubject:"operator_1",approverSubject:"reviewer_2",
  scopeDigest:"a".repeat(64),approvalDigest:"b".repeat(64),
  expiresAt:Date.now()+90_000
};
function snapshot(query:InstitutionalEvidenceQuery):InstitutionalEvidenceSnapshot {
  return {...query,revision:7,status:"open",decision:"approved",
    reviewerSubject:query.approverSubject,checkedAt:now(),reviewedAt:now()-20,
    mfaVerifiedAt:now()-30,validUntil:now()+60};
}
const reader=(overrides:Partial<InstitutionalEvidenceSnapshot>={})=>({
  readCurrentEvidence:vi.fn(async(q:InstitutionalEvidenceQuery)=>({...snapshot(q),...overrides}))
});
describe("R2.12b · current institutional evidence contract (offline synthetic)",()=>{
  it("requires an independently obtained, current, exactly bound human decision",async()=>{
    const port=reader();
    const proof=await checkCurrentInstitutionalEvidence(port,scope);
    expect(proof).toEqual({revision:7,checkedAt:expect.any(Number)});
    expect(port.readCurrentEvidence).toHaveBeenCalledOnce();
    expect(port.readCurrentEvidence).toHaveBeenCalledWith(scope);
  });
  it.each([
    {status:"closed"},{decision:"rejected"},{revision:0},
    {caseRef:"INC_OTHER"},{requestId:"other"},{actorSubject:"different"},
    {approverSubject:"different"},{reviewerSubject:"different"},
    {scopeDigest:"c".repeat(64)},{approvalDigest:"c".repeat(64)},
    {checkedAt:now()-60},{checkedAt:now()+60},{reviewedAt:now()+60},
    {mfaVerifiedAt:now()-900},{mfaVerifiedAt:now()+60},
    {validUntil:now()-5},{revision:1.5},{purpose:"redrive"}
  ] as Partial<InstitutionalEvidenceSnapshot>[])(
    "denies stale, closed, unbound, or inconsistent case evidence: %j",
    async invalid=>{
      await expect(checkCurrentInstitutionalEvidence(reader(invalid),scope))
        .rejects.toBeInstanceOf(InstitutionalEvidenceDenied);
    }
  );
  it("never treats a missing, throwing or empty institutional source as approval",async()=>{
    await expect(checkCurrentInstitutionalEvidence(undefined,scope))
      .rejects.toBeInstanceOf(InstitutionalEvidenceUnavailable);
    await expect(checkCurrentInstitutionalEvidence({
      readCurrentEvidence:async()=>{throw new Error("incident system down and token leaked");}
    },scope)).rejects.toBeInstanceOf(InstitutionalEvidenceUnavailable);
    await expect(checkCurrentInstitutionalEvidence({
      readCurrentEvidence:async()=>null
    },scope)).rejects.toBeInstanceOf(InstitutionalEvidenceDenied);
  });
  it("rejects expired signed decisions regardless of a current institutional record",async()=>{
    await expect(checkCurrentInstitutionalEvidence(reader(),{
      ...scope,expiresAt:Date.now()-1
    })).rejects.toBeInstanceOf(InstitutionalEvidenceDenied);
  });
});
