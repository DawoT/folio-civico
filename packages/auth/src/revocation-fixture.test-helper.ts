import {vi} from "vitest";
import {exportJWK,generateKeyPair,SignJWT} from "jose";
import {verifyRevocationAuthorization,type RevocationAuthorizationConfig,
  type RevocationScope,type RevocationEvidence} from "./revocation-authorization";

const accessIssuer="https://revocation-fixture.cloudflareaccess.com";
const incidentIssuer="https://incident-approval.test";
const actor="incident_operator_001";
const approver="incident_approver_002";
const defaults={
  kind:"image" as const,
  target:"sha256:"+"d".repeat(64),
  incidentRef:"INC_20261119_REVOCATION",
  requestKey:"revocation_request_0001",
  reason:"Confirmed synthetic inspector image recall requiring immediate preventive denial."
};
let cache:ReturnType<typeof makeKeys>|undefined;
async function makeKeys() {
  const [access,incident]=await Promise.all([
    generateKeyPair("RS256"),generateKeyPair("RS256")
  ]);
  const [accessJwk,incidentJwk]=await Promise.all([
    exportJWK(access.publicKey),exportJWK(incident.publicKey)
  ]);
  accessJwk.kid="access-revocation-synthetic";
  incidentJwk.kid="incident-revocation-synthetic";
  return {access,incident,accessJwk,incidentJwk};
}
export async function revocationFixture(overrides:Partial<RevocationScope>={}) {
  const keys=await (cache??=makeKeys());
  const now=Math.floor(Date.now()/1000);
  const scope:RevocationScope={...defaults,...overrides};
  const config:RevocationAuthorizationConfig={
    ACCESS_TEAM_DOMAIN:accessIssuer,
    ACCESS_AUD:"folio-revocation-authority",
    configuredIncidentActorSubject:actor,
    configuredIncidentApproverSubject:approver,
    incidentAuthority:{
      issuer:incidentIssuer,audience:"folio-incident-approval",
      publicJwk:keys.incidentJwk
    }
  };
  const requestWithAccess=(jwt:string)=>new Request("https://operator.local/private-revocation",{
    headers:{"Cf-Access-Jwt-Assertion":jwt}
  });
  const signAccess=async(subject=actor,expired=false)=>{
    const signer=new SignJWT({}).setProtectedHeader({
      alg:"RS256",kid:keys.accessJwk.kid
    }).setSubject(subject).setIssuer(accessIssuer)
      .setAudience(config.ACCESS_AUD!).setIssuedAt()
      .setExpirationTime(expired?now-5:now+600);
    return signer.sign(keys.access.privateKey);
  };
  const signApproval=async(changes:Record<string,unknown>={},
    options:{expired?:boolean;wrongKey?:boolean;issuer?:string;audience?:string}={})=>{
    const targetHash=await revocationTargetDigest(scope.kind,scope.target);
    const reasonHash=await revocationReasonDigest(scope.reason);
    return new SignJWT({
      purpose:"folio.redrive.revocation.approval.v1",
      kind:scope.kind,targetHash,reasonHash,incidentRef:scope.incidentRef,
      requestKey:scope.requestKey,actorSubject:actor,approverSubject:approver,
      decision:"approved",mfa:"verified",mfaAt:now,...changes
    }).setProtectedHeader({
      alg:"RS256",kid:keys.incidentJwk.kid
    }).setIssuer(options.issuer??incidentIssuer)
      .setAudience(options.audience??config.incidentAuthority!.audience)
      .setSubject(approver)
      .setIssuedAt()
      .setExpirationTime(options.expired?now-5:now+180)
      .sign(options.wrongKey?keys.access.privateKey:keys.incident.privateKey);
  };
  vi.stubGlobal("fetch",vi.fn(async()=>Response.json({keys:[keys.accessJwk]})));
  const evidence:RevocationEvidence={
    actorAccessRequest:requestWithAccess(await signAccess(actor)),
    approverAccessRequest:requestWithAccess(await signAccess(approver)),
    approvalJwt:await signApproval()
  };
  return {
    config,scope,evidence,keys,actor,approver,requestWithAccess,signAccess,
    signApproval,verify:()=>verifyRevocationAuthorization(config,evidence,scope)
  };
}

// Same canon as verifier, used only in synthetic tests.
async function hash(parts:unknown):Promise<string> {
  const bytes=new TextEncoder().encode(JSON.stringify(parts));
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)))
    .map(x=>x.toString(16).padStart(2,"0")).join("");
}
export async function revocationTargetDigest(kind:string,target:string):Promise<string>{
  return hash([kind,target]);
}
export async function revocationReasonDigest(reason:string):Promise<string>{
  return hash(reason.trim());
}
