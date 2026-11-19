import {afterEach,describe,expect,it,vi} from "vitest";
import {
  verifyRevocationAuthorization,isVerifiedRevocationAuthorization,
  RevocationAuthorizationError
} from "./revocation-authorization";
import {revocationFixture} from "./revocation-fixture.test-helper";

afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();});

describe("R2.8 · independent signed incident revocation approvals",()=>{
  it("requires two distinct Access principals and a signed operation-specific incident approval",async()=>{
    const f=await revocationFixture();
    const proof=await f.verify();
    expect(proof).toMatchObject({
      actorSubject:f.actor,approverSubject:f.approver,
      kind:f.scope.kind,incidentRef:f.scope.incidentRef,
      requestKey:f.scope.requestKey
    });
    expect(proof.targetHash).toMatch(/^[a-f0-9]{64}$/);
    expect(proof.reasonHash).toMatch(/^[a-f0-9]{64}$/);
    expect(proof.approvalDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(await isVerifiedRevocationAuthorization(proof,{
      ...f.scope,actorSubject:f.actor,approverSubject:f.approver
    })).toBe(true);
    expect(await isVerifiedRevocationAuthorization({...proof},{
      ...f.scope,actorSubject:f.actor,approverSubject:f.approver
    })).toBe(false);
    const clock=vi.spyOn(Date,"now").mockReturnValue(proof.expiresAt+1);
    expect(await isVerifiedRevocationAuthorization(proof,{
      ...f.scope,actorSubject:f.actor,approverSubject:f.approver
    })).toBe(false);
    clock.mockRestore();
  });

  it("fails closed for missing/forged Access JWTs, self-approval and unconfigured actor/approver",async()=>{
    const f=await revocationFixture();
    const badEvidence=[
      {...f.evidence,actorAccessRequest:new Request("https://operator.test")},
      {...f.evidence,actorAccessRequest:f.requestWithAccess("not-a-jwt")},
      {...f.evidence,approverAccessRequest:f.requestWithAccess(await f.signAccess(f.actor))},
      {...f.evidence,actorAccessRequest:f.requestWithAccess(await f.signAccess("stranger"))},
      {...f.evidence,approverAccessRequest:f.requestWithAccess(await f.signAccess("stranger"))},
      {...f.evidence,approverAccessRequest:f.requestWithAccess(await f.signAccess(f.approver,true))}
    ];
    for(const evidence of badEvidence){
      await expect(verifyRevocationAuthorization(f.config,evidence,f.scope))
        .rejects.toBeInstanceOf(RevocationAuthorizationError);
    }
    const badConfigs=[
      {...f.config,configuredIncidentActorSubject:undefined},
      {...f.config,configuredIncidentApproverSubject:undefined},
      {...f.config,configuredIncidentApproverSubject:f.actor},
      {...f.config,configuredIncidentActorSubject:f.approver},
      {...f.config,incidentAuthority:undefined},
      {...f.config,ACCESS_AUD:"wrong-aud"},
      {...f.config,incidentAuthority:{...f.config.incidentAuthority!,issuer:f.config.ACCESS_TEAM_DOMAIN!}}
    ];
    for(const config of badConfigs){
      await expect(verifyRevocationAuthorization(config,f.evidence,f.scope))
        .rejects.toBeInstanceOf(RevocationAuthorizationError);
    }
  });

  it("rejects invalid, tampered, stale and wrong-authority approval tokens",async()=>{
    const f=await revocationFixture();
    const approvals=[
      "invalid",
      await f.signApproval({}, {expired:true}),
      await f.signApproval({}, {wrongKey:true}),
      await f.signApproval({}, {issuer:"https://wrong-issuer.test"}),
      await f.signApproval({}, {audience:"wrong-audience"}),
      await f.signApproval({purpose:"folio.manual-redrive.approval.v1"}),
      await f.signApproval({actorSubject:f.approver}),
      await f.signApproval({approverSubject:f.actor}),
      await f.signApproval({decision:"rejected"}),
      await f.signApproval({mfa:"not_verified"}),
      await f.signApproval({mfaAt:Math.floor(Date.now()/1000)-7200}),
      await f.signApproval({mfaAt:Math.floor(Date.now()/1000)+7200}),
      await f.signApproval({kind:"operator"}),
      await f.signApproval({targetHash:"f".repeat(64)}),
      await f.signApproval({reasonHash:"a".repeat(64)}),
      await f.signApproval({incidentRef:"INC_DIFFERENT_0001"}),
      await f.signApproval({requestKey:"wrong_request_001"})
    ];
    for(const approvalJwt of approvals){
      await expect(verifyRevocationAuthorization(f.config,{
        ...f.evidence,approvalJwt
      },f.scope)).rejects.toBeInstanceOf(RevocationAuthorizationError);
    }
  });

  it("rejects malformed global revocation targets, incident refs and unsafe rationale",async()=>{
    const f=await revocationFixture();
    for(const scope of [
      {...f.scope,kind:"unknown" as never},
      {...f.scope,target:"sha256:nothex"},
      {...f.scope,target:"sha256:"+"F".repeat(64)},
      {...f.scope,incidentRef:"../unsafe"},
      {...f.scope,requestKey:"short"},
      {...f.scope,reason:"too short"},
      {...f.scope,reason:"x".repeat(601)},
      {...f.scope,reason:"text\nwith newline"+ " ".repeat(28)}
    ]){
      await expect(verifyRevocationAuthorization(f.config,f.evidence,scope))
        .rejects.toBeInstanceOf(RevocationAuthorizationError);
    }
  });
});
