import {vi} from "vitest";
import {exportJWK,generateKeyPair,SignJWT} from "jose";
import {
  verifyOneShotOperatorAuthorization,type OperatorPreflightConfig,
  type OneShotAuthorizationScope
} from "./manual-redrive-authorization";

/** Synthetic trusted authorities and tokens. Never shipped to runtime. */
const issuer="https://operator-fixture.cloudflareaccess.com";
const approvalIssuer="https://approval-authority.test";
const releaseIssuer="https://inspector-release.test";
const imageDigest="sha256:"+"d".repeat(64);
const operatorSubject="operator_authorized_001";
const approvalRef="OPR_20261119_001";

let keysPromise:ReturnType<typeof buildKeys>|undefined;
async function buildKeys(){
  const [access,approval,release]=await Promise.all([
    generateKeyPair("RS256"),generateKeyPair("RS256"),generateKeyPair("RS256")
  ]);
  const [accessJwk,approvalJwk,releaseJwk]=await Promise.all([
    exportJWK(access.publicKey),exportJWK(approval.publicKey),
    exportJWK(release.publicKey)
  ]);
  accessJwk.kid="access-operator-fixture";
  approvalJwk.kid="approval-operator-fixture";
  releaseJwk.kid="release-operator-fixture";
  return {access,approval,release,accessJwk,approvalJwk,releaseJwk};
}
export async function syntheticOperatorAuthorization(
  overrides:Partial<OneShotAuthorizationScope>={}
){
  const keys=await (keysPromise??=buildKeys());
  const now=Math.floor(Date.now()/1000);
  const scope:OneShotAuthorizationScope={
    commissionId:"c_a",reviewId:"review_fixture",
    requestKey:"operator_redrive_0001",approvalRef,...overrides
  };
  const config:OperatorPreflightConfig={
    ACCESS_TEAM_DOMAIN:issuer,ACCESS_AUD:"folio-operator-e2e",
    configuredOperatorSubject:operatorSubject,
    approvalAuthority:{
      issuer:approvalIssuer,audience:"folio-operator-approval",
      publicJwk:keys.approvalJwk
    },
    releaseAuthority:{
      issuer:releaseIssuer,audience:"folio-inspector-release",
      publicJwk:keys.releaseJwk
    },
    requiredImageDigest:imageDigest
  };
  const signing=async(
    kind:"access"|"approval"|"release",
    changes:Record<string,unknown>={},
    opts?:{issuer?:string;audience?:string;keyKind?:"access"|"approval"|"release";expired?:boolean}
  )=>{
    const values:Record<string,unknown>=kind==="approval"?{
      purpose:"folio.manual-redrive.approval.v1",...scope,
      operatorSubject,decision:"approved",mfa:"verified",mfaAt:now
    }:kind==="release"?{
      purpose:"folio.inspector.release.v1",imageDigest,cveGate:"pass",
      sbomSha256:"e".repeat(64),auditSha256:"f".repeat(64),
      auditedAt:now,signaturesFreshUntil:now+3600
    }:{};
    const selected=opts?.keyKind??kind;
    const key=keys[selected];
    const jws=new SignJWT({...values,...changes})
      .setProtectedHeader({alg:"RS256",kid:{
        access:keys.accessJwk.kid,approval:keys.approvalJwk.kid,
        release:keys.releaseJwk.kid
      }[selected]})
      .setIssuer(opts?.issuer??{access:issuer,approval:approvalIssuer,
        release:releaseIssuer}[kind])
      .setAudience(opts?.audience??{access:"folio-operator-e2e",
        approval:"folio-operator-approval",
        release:"folio-inspector-release"}[kind])
      .setIssuedAt();
    if(opts?.expired)jws.setExpirationTime(now-30);
    else jws.setExpirationTime(kind==="approval"?"4m":kind==="access"?"10m":"2h");
    if(kind==="access")jws.setSubject((changes.sub as string|undefined)??operatorSubject);
    return jws.sign(key.privateKey);
  };
  vi.stubGlobal("fetch",vi.fn(async()=>Response.json({keys:[keys.accessJwk]})));
  const requestWithAccess=(token:string)=>new Request("https://operator.local/private-redrive",{
    headers:{"Cf-Access-Jwt-Assertion":token}
  });
  const accessJwt=await signing("access");
  const evidence={
    accessRequest:requestWithAccess(accessJwt),
    approvalJwt:await signing("approval"),
    releaseJwt:await signing("release")
  };
  return {
    keys,config,scope,evidence,signing,requestWithAccess,
    verify:()=>verifyOneShotOperatorAuthorization(config,evidence,scope)
  };
}
