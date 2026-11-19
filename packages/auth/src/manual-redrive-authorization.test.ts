import {afterEach,describe,expect,it,vi} from "vitest";
import {
  isVerifiedRedriveAuthorization,OperatorAuthorizationError,
  verifyOneShotOperatorAuthorization
} from "./manual-redrive-authorization";
import {syntheticOperatorAuthorization} from "./signed-fixture.test-helper";

afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();});

function corruptJwtSignature(token:string):string {
  const parts=token.split(".");
  const signature=parts[2];
  if(parts.length!==3 || !signature)throw new Error("Invalid signed test token");
  // Change six significant bits, not the possibly non-significant trailing
  // Base64URL bits (which can decode to an unchanged RSA signature).
  parts[2]=(signature[0]==="A"?"B":"A")+signature.slice(1);
  return parts.join(".");
}

describe("R2.6 · independent signed operator + MFA approval + inspector release preflight",()=>{
  it("verifies three separate signed authorities, scopes and finite expiry; prevents forged proof objects",async()=>{
    const f=await syntheticOperatorAuthorization();
    const auth=await f.verify();
    expect(auth).toMatchObject({
      operatorSubject:"operator_authorized_001",
      commissionId:f.scope.commissionId,reviewId:f.scope.reviewId,
      requestKey:f.scope.requestKey,approvalRef:f.scope.approvalRef,
      imageDigest:f.config.requiredImageDigest
    });
    const expected={...f.scope,operatorSubject:"operator_authorized_001",
      imageDigest:f.config.requiredImageDigest!};
    expect(isVerifiedRedriveAuthorization(auth,expected)).toBe(true);
    expect(isVerifiedRedriveAuthorization({...auth},expected)).toBe(false);
    expect(isVerifiedRedriveAuthorization({
      ...auth,expiresAt:Date.now()+100_000
    },expected)).toBe(false);
    expect(isVerifiedRedriveAuthorization(null,expected)).toBe(false);
    expect(isVerifiedRedriveAuthorization(auth,{...expected,requestKey:"different_key"})).toBe(false);
    expect(isVerifiedRedriveAuthorization(auth,{...expected,imageDigest:"sha256:"+"0".repeat(64)})).toBe(false);
    expect(auth.attestationDigest).toMatch(/^[a-f0-9]{64}$/);
    const clock=vi.spyOn(Date,"now").mockReturnValue(auth.expiresAt+10);
    expect(isVerifiedRedriveAuthorization(auth,expected)).toBe(false);
    clock.mockRestore();
  });

  it("rejects absent or forged Access assertions and unconfigured/wrong operator roots",async()=>{
    const f=await syntheticOperatorAuthorization();
    for(const modified of [
      {...f.evidence,accessRequest:new Request("https://operator.local")},
      {...f.evidence,accessRequest:f.requestWithAccess("forged")},
      {...f.evidence,accessRequest:f.requestWithAccess(
        await f.signing("access",{sub:"another_operator"})
      )}
    ]){
      await expect(verifyOneShotOperatorAuthorization(f.config,modified,f.scope))
        .rejects.toBeInstanceOf(OperatorAuthorizationError);
    }
    for(const config of [
      {...f.config,ACCESS_AUD:"unrelated-audience"},
      {...f.config,ACCESS_TEAM_DOMAIN:"https://evil.example.test"},
      {...f.config,configuredOperatorSubject:"another_operator"},
      {...f.config,configuredOperatorSubject:undefined},
      {...f.config,releaseAuthority:undefined},
      {...f.config,requiredImageDigest:undefined},
      {...f.config,approvalAuthority:{...f.config.approvalAuthority!,issuer:f.config.releaseAuthority!.issuer}},
      {...f.config,releaseAuthority:{...f.config.releaseAuthority!,publicJwk:f.keys.approvalJwk}}
    ]){
      await expect(verifyOneShotOperatorAuthorization(config,f.evidence,f.scope))
        .rejects.toBeInstanceOf(OperatorAuthorizationError);
    }
  });

  it("rejects forged, expired, wrong signer/issuer/audience or operation-swapped approval JWT",async()=>{
    const f=await syntheticOperatorAuthorization();
    for(const approvalJwt of [
      "a.b.c",
      corruptJwtSignature(f.evidence.approvalJwt),
      await f.signing("approval",{}, {expired:true}),
      await f.signing("approval",{}, {keyKind:"release"}),
      await f.signing("approval",{}, {issuer:"https://evil.test"}),
      await f.signing("approval",{}, {audience:"unrelated-approval"}),
      await f.signing("approval",{commissionId:"c_b"}),
      await f.signing("approval",{reviewId:"different_review"}),
      await f.signing("approval",{requestKey:"other_request_001"}),
      await f.signing("approval",{approvalRef:"OPR_other_2026"}),
      await f.signing("approval",{operatorSubject:"another_subject"}),
      await f.signing("approval",{decision:"rejected"}),
      await f.signing("approval",{purpose:"folio.generic"}),
      await f.signing("approval",{mfa:"not_verified"}),
      await f.signing("approval",{mfaAt:Math.floor(Date.now()/1000)-7200}),
      await f.signing("approval",{mfaAt:Math.floor(Date.now()/1000)+7200})
    ]){
      await expect(verifyOneShotOperatorAuthorization(f.config,{
        ...f.evidence,approvalJwt
      },f.scope)).rejects.toBeInstanceOf(OperatorAuthorizationError);
    }
  });

  it("rejects forged, expired, stale, and mis-bound inspector release attestations",async()=>{
    const f=await syntheticOperatorAuthorization();
    for(const releaseJwt of [
      "malformed",
      await f.signing("release",{}, {expired:true}),
      await f.signing("release",{}, {keyKind:"approval"}),
      await f.signing("release",{}, {issuer:"https://untrusted-release.test"}),
      await f.signing("release",{}, {audience:"not-inspector-release"}),
      await f.signing("release",{purpose:"other-release"}),
      await f.signing("release",{imageDigest:"sha256:"+"1".repeat(64)}),
      await f.signing("release",{cveGate:"blocked"}),
      await f.signing("release",{sbomSha256:"invalid"}),
      await f.signing("release",{auditSha256:"invalid"}),
      await f.signing("release",{auditedAt:Math.floor(Date.now()/1000)-48*3600}),
      await f.signing("release",{signaturesFreshUntil:Math.floor(Date.now()/1000)-1}),
      await f.signing("release",{signaturesFreshUntil:Math.floor(Date.now()/1000)+80*3600})
    ]){
      await expect(verifyOneShotOperatorAuthorization(f.config,{
        ...f.evidence,releaseJwt
      },f.scope)).rejects.toBeInstanceOf(OperatorAuthorizationError);
    }
  });

  it("rejects altered, truncated and unscoped operator approval fields",async()=>{
    const f=await syntheticOperatorAuthorization();
    for(const scope of [
      {...f.scope,commissionId:"wrong#id"},
      {...f.scope,reviewId:""},
      {...f.scope,requestKey:"short"},
      {...f.scope,approvalRef:"INC_not_an_operator_approval"}
    ]){
      await expect(verifyOneShotOperatorAuthorization(f.config,f.evidence,scope))
        .rejects.toBeInstanceOf(OperatorAuthorizationError);
    }
  });
});
