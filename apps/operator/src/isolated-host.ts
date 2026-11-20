import {
  verifyRevocationAuthorization,RevocationAuthorizationError,
  verifyOneShotOperatorAuthorization,OperatorAuthorizationError,
  type RevocationScope,type RevocationAuthorizationConfig,
  type OperatorPreflightConfig,
  verifyAsyncIncidentActor,verifyAsyncIncidentApprover,
  verifyAsyncIncidentDecision,AsyncRevocationAccessError,
  verifyAsyncRedriveRequester,verifyAsyncRedriveDecision,
  signedHash
} from "../../../packages/auth/src/index";
import {
  registerRedriveRevocation,RevocationRegistrationAccessError,
  RevocationRegistrationConflictError
} from "../../../packages/data/src/revocation-registration";
import {
  executeOneShotManualRedrive,ManualRedriveAccessError,
  ManualRedriveConflictError,ManualRedriveInputError
} from "../../../packages/data/src/manual-redrive";
import type {ProcessingQueueMessage} from "../../../packages/data/src/processing-outbox";
import {findInstitutionalEvidence,type InstitutionalEvidenceReceipt} from "../../../packages/data/src/institutional-approval-journal";
import {
  checkCurrentInstitutionalEvidence,
  InstitutionalEvidenceDenied,InstitutionalEvidenceUnavailable,
  type InstitutionalEvidenceReader,type InstitutionalEvidenceQuery
} from "./institutional-authority";
import {
  proposeAsyncRedrive,findAsyncRedrive,approveAsyncRedrive,
  AsyncRedriveAccessError,AsyncRedriveConflictError
} from "../../../packages/data/src/async-redrive";
import {
  proposeAsyncRevocation,findAsyncRevocation,approveAsyncRevocation,
  AsyncRevocationDenied,AsyncRevocationConflict
} from "../../../packages/data/src/async-revocation";

/**
 * R2.9–R2.11: a synthetic-only private HTTP adapter, not a Cloudflare Worker.
 *
 * Deliberately no default ExportedHandler, Wrangler config, deployment
 * binding, route registration, secrets, or production hostname. A future
 * operator host needs independent resource/IdP/CVE approvals.
 */
export interface IsolatedOperatorConfig {
  /** Exact opt-in solely for synthetic local integration tests. */
  mode?:"synthetic-offline-only";
  db?:D1Database;
  revocationTrust?:RevocationAuthorizationConfig;
  /** R2.8 combined-token route is disabled unless explicitly enabled for legacy tests. */
  allowLegacyCombinedRevocations?:boolean;
  redriveTrust?:OperatorPreflightConfig;
  /** Deprecated single-request execution; OFF except explicit legacy tests. */
  allowLegacyDirectRedrives?:boolean;
  /** Injected fake Queue in local tests; NEVER a live binding here. */
  queue?:{send(message:ProcessingQueueMessage):Promise<unknown>};
  /** Trusted image identity, never from a client-supplied JSON body. */
  runtimeInspectorImageDigest?:string;
  /**
   * R2.12b staged institutional preflight. Explicitly opt in for synthetic
   * contract tests. With an empty gate object, ALL protected decisions fail
   * closed. Never supplied by a client or wired to a production host.
   */
  institutionalGate?:Readonly<{reader?:InstitutionalEvidenceReader}>;
}

const TEST_ORIGIN="https://operator.local";
const PATH="/internal/operations/";
const MAX_BODY_BYTES=8192;
const JWT=/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const IMAGE=/^sha256:[0-9a-f]{64}$/;
const SECURITY_HEADERS={
  "Cache-Control":"no-store",
  "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options":"nosniff",
  "Referrer-Policy":"no-referrer",
  "Cross-Origin-Resource-Policy":"same-origin"
} as const;

class BadInput extends Error {}
class TooLarge extends Error {}
async function requireInstitutionalGate(
  config:IsolatedOperatorConfig,query:InstitutionalEvidenceQuery,
  required:boolean,alreadyApproved=false
):Promise<InstitutionalEvidenceReceipt|undefined>{
  // D1 remembers the opt-in independently of current host configuration.
  // A replay or execution cannot drop its read by removing the config field.
  const existing=await findInstitutionalEvidence(
    config.db!,query.purpose,query.requestId
  );
  if(alreadyApproved && (required || existing) && !existing){
    throw new InstitutionalEvidenceDenied("Institutional approval receipt missing");
  }
  if(!required && !config.institutionalGate && !existing)return undefined;
  const evidence=await checkCurrentInstitutionalEvidence(
    config.institutionalGate?.reader,query
  );
  if(existing && (
    existing.caseRevision!==evidence.revision
    || existing.scopeDigest!==query.scopeDigest
    || existing.approvalDigest!==query.approvalDigest
    || existing.actorSubject!==query.actorSubject
    || existing.approverSubject!==query.approverSubject
    || existing.expiresAt*1000!==query.expiresAt
  )){
    throw new InstitutionalEvidenceDenied("Institutional case revision changed");
  }
  return Object.freeze({
    caseRevision:evidence.revision,
    checkedAt:evidence.checkedAt,scopeDigest:query.scopeDigest
  });
}
async function redriveScopeDigest(stored:{
  commissionId:string;reviewId:string;requestKey:string;approvalRef:string
}):Promise<string>{
  return signedHash([
    stored.commissionId,stored.reviewId,stored.requestKey,stored.approvalRef
  ]);
}

function response(status:number,body:object):Response {
  return new Response(JSON.stringify(body),{
    status,
    headers:{"Content-Type":"application/json; charset=utf-8",...SECURITY_HEADERS}
  });
}
function failed(status:number):Response {
  const message=status===403?"Forbidden"
    :status===404?"Not found"
    :status===405?"Method not allowed"
    :status===413?"Payload too large"
    :status===415?"Unsupported media type"
    :status===409?"Conflict"
    :status===400?"Invalid request":"Service unavailable";
  return response(status,{error:message});
}
function token(request:Request,name:string):string {
  const value=request.headers.get(name);
  if(!value || value.length>8192 || !JWT.test(value))
    throw new OperatorAuthorizationError("Required signed assertion missing");
  return value;
}
function fields(value:unknown,expected:readonly string[]):Record<string,string> {
  if(!value || typeof value!=="object" || Array.isArray(value))
    throw new BadInput("Expected one JSON object");
  const entries=Object.entries(value);
  if(entries.length!==expected.length
    || entries.some(([key,v])=>!expected.includes(key)||typeof v!=="string")) {
    throw new BadInput("Unexpected or missing operation field");
  }
  return value as Record<string,string>;
}
async function jsonBody(request:Request):Promise<unknown> {
  const contentLength=request.headers.get("Content-Length");
  if(contentLength!==null){
    if(!/^[0-9]{1,5}$/.test(contentLength))throw new BadInput("Invalid content length");
    if(Number(contentLength)>MAX_BODY_BYTES)throw new TooLarge();
  }
  const raw=await request.text();
  if(new TextEncoder().encode(raw).byteLength>MAX_BODY_BYTES)throw new TooLarge();
  try{return JSON.parse(raw) as unknown;}catch{throw new BadInput("Invalid JSON");}
}
function independentApproverRequest(request:Request):Request {
  const assertion=token(request,"X-Folio-Approver-Access-Jwt");
  return new Request(TEST_ORIGIN+"/approver-access-check",{
    headers:{"Cf-Access-Jwt-Assertion":assertion}
  });
}
function forbiddenBrowserRequest(request:Request):boolean {
  return request.headers.has("Origin") || request.headers.has("Cookie")
    || request.headers.has("Sec-WebSocket-Key");
}

/**
 * A request-aware adapter for the EXISTING verifier and D1 one-shot writer.
 * Reconstruct a real signed-identity trust boundary; never trust subjects,
 * configured roots, image digest or queue bindings from request JSON.
 */
export async function handleIsolatedOperatorRequest(
  request:Request,config:IsolatedOperatorConfig
):Promise<Response> {
  // Fail closed before even parsing request bodies or verifying JWTs.
  if(config.mode!=="synthetic-offline-only" || !config.db) return failed(503);
  try{
    const url=new URL(request.url);
    if(url.origin!==TEST_ORIGIN || url.search || url.hash
      || ![PATH+"revocations",PATH+"redrives",
        PATH+"revocation-proposals",PATH+"revocation-approvals",
        PATH+"redrive-proposals",PATH+"redrive-approvals",
        PATH+"redrive-executions"].includes(url.pathname))
      return failed(404);
    if(request.method!=="POST")return failed(405);
    if(forbiddenBrowserRequest(request))return failed(403);
    if(!/^application\/json(?:;\s*charset=utf-8)?$/i.test(
      request.headers.get("Content-Type")??""
    ))return failed(415);

    // R2.10: only the initiating actor's Access JWT is present in stage 1.
    if(url.pathname===PATH+"revocation-proposals"){
      if(request.headers.has("X-Folio-Approver-Access-Jwt")
        || request.headers.has("X-Folio-Incident-Approval-Jws"))return failed(403);
      if(!config.revocationTrust)return failed(503);
      const scope=fields(await jsonBody(request),[
        "kind","target","incidentRef","requestKey","reason"
      ]) as unknown as RevocationScope;
      const actorProof=await verifyAsyncIncidentActor(config.revocationTrust,request);
      const result=await proposeAsyncRevocation(config.db,scope,actorProof,
        Boolean(config.institutionalGate));
      return response(202,result);
    }
    // R2.10: stage 2 receives only the approver's independent Access JWT,
    // and a signed approval JWS from the incident authority. The actor JWT
    // is never stored in D1 and is not required in this separate request.
    if(url.pathname===PATH+"revocation-approvals"){
      if(request.headers.has("X-Folio-Approver-Access-Jwt"))return failed(403);
      if(!config.revocationTrust)return failed(503);
      const {requestId}=fields(await jsonBody(request),["requestId"]);
      const approverProof=await verifyAsyncIncidentApprover(config.revocationTrust,request);
      const stored=await findAsyncRevocation(config.db,requestId!);
      if(!stored)return failed(403);
      const decision=await verifyAsyncIncidentDecision(
        config.revocationTrust,approverProof,
        token(request,"X-Folio-Incident-Approval-Jws"),stored
      );
      const evidence=await requireInstitutionalGate(config,{
        purpose:"revocation",caseRef:stored.incidentRef,
        requestId:stored.id,actorSubject:stored.actorSubject,
        approverSubject:decision.approverSubject,
        scopeDigest:await signedHash([
          stored.kind,stored.targetHash,stored.reasonHash,
          stored.requestKey,stored.incidentRef
        ]),
        approvalDigest:decision.approvalDigest,
        expiresAt:stored.expiresAt*1000
      },Boolean(stored.institutionalGateRequired),stored.status==="approved");
      const result=await approveAsyncRevocation(config.db,stored,decision,evidence);
      return response(200,result);
    }
    // Legacy R2.9 combined two-token route remains testable but is OFF by
    // default. It is not suitable for live human separation of duties.
    if(url.pathname===PATH+"revocations"){
      if(!config.allowLegacyCombinedRevocations)return failed(404);
      if(!config.revocationTrust)return failed(503);
      const scope=fields(await jsonBody(request),[
        "kind","target","incidentRef","requestKey","reason"
      ]) as unknown as RevocationScope;
      const proof=await verifyRevocationAuthorization(config.revocationTrust,{
        actorAccessRequest:request,
        approverAccessRequest:independentApproverRequest(request),
        approvalJwt:token(request,"X-Folio-Incident-Approval-Jws")
      },scope);
      const outcome=await registerRedriveRevocation(config.db,scope,proof);
      return response(200,outcome);
    }
    // R2.11: separate Access identity for each human and a third, narrowly
    // bound operator execution; the approver's Access JWT is never shared.
    if(url.pathname===PATH+"redrive-proposals"){
      if(!config.redriveTrust)return failed(503);
      if(request.headers.has("X-Folio-Redrive-Approval-Jws")
        || request.headers.has("X-Folio-Inspector-Release-Jws")
        || request.headers.has("X-Folio-Approver-Access-Jwt"))return failed(403);
      const scope=fields(await jsonBody(request),[
        "commissionId","reviewId","requestKey","approvalRef"
      ]);
      const operator=await verifyAsyncRedriveRequester(config.redriveTrust,request);
      const result=await proposeAsyncRedrive(config.db,{
        commissionId:scope.commissionId!,reviewId:scope.reviewId!,
        requestKey:scope.requestKey!,approvalRef:scope.approvalRef!
      },operator,Boolean(config.institutionalGate));
      return response(202,result);
    }
    if(url.pathname===PATH+"redrive-approvals"){
      if(!config.redriveTrust)return failed(503);
      if(request.headers.has("X-Folio-Approver-Access-Jwt")
        || request.headers.has("X-Folio-Inspector-Release-Jws"))return failed(403);
      const {requestId}=fields(await jsonBody(request),["requestId"]);
      const stored=await findAsyncRedrive(config.db,requestId!);
      if(!stored)return failed(403);
      const proof=await verifyAsyncRedriveDecision(
        config.redriveTrust,request,token(request,"X-Folio-Redrive-Approval-Jws"),
        stored
      );
      const evidence=await requireInstitutionalGate(config,{
        purpose:"redrive",caseRef:stored.approvalRef,
        requestId:stored.id,actorSubject:stored.operatorSubject,
        approverSubject:proof.approverSubject,
        scopeDigest:await redriveScopeDigest(stored),
        approvalDigest:proof.approvalDigest,
        expiresAt:stored.expiresAt*1000
      },Boolean(stored.institutionalGateRequired),stored.status==="approved");
      return response(200,await approveAsyncRedrive(config.db,stored,proof,evidence));
    }
    if(url.pathname===PATH+"redrive-executions"){
      if(request.headers.has("X-Folio-Approver-Access-Jwt"))return failed(403);
      if(!config.redriveTrust || !config.queue
        || !IMAGE.test(config.runtimeInspectorImageDigest??"")
        || config.runtimeInspectorImageDigest!==config.redriveTrust.requiredImageDigest)
        return failed(503);
      const {requestId}=fields(await jsonBody(request),["requestId"]);
      const stored=await findAsyncRedrive(config.db,requestId!);
      if(!stored || stored.status!=="approved"
        || stored.expiresAt*1000<=Date.now()
        || stored.approverSubject!==config.redriveTrust.configuredRedriveApproverSubject)
        return failed(403);
      const approvalJwt=token(request,"X-Folio-Redrive-Approval-Jws");
      if(await signedHash(approvalJwt)!==stored.approvalDigest)return failed(403);
      const proof=await verifyOneShotOperatorAuthorization(config.redriveTrust,{
        accessRequest:request,approvalJwt,
        releaseJwt:token(request,"X-Folio-Inspector-Release-Jws")
      },{
        commissionId:stored.commissionId,reviewId:stored.reviewId,
        requestKey:stored.requestKey,approvalRef:stored.approvalRef
      });
      if(proof.operatorSubject!==stored.operatorSubject)return failed(403);
      await requireInstitutionalGate(config,{
        purpose:"redrive",caseRef:stored.approvalRef,
        requestId:stored.id,actorSubject:stored.operatorSubject,
        approverSubject:stored.approverSubject,
        scopeDigest:await redriveScopeDigest(stored),
        approvalDigest:stored.approvalDigest!,
        expiresAt:stored.expiresAt*1000
      },Boolean(stored.institutionalGateRequired),true);
      const outcome=await executeOneShotManualRedrive({
        DB:config.db,QUEUE:config.queue,authorization:proof,
        requiredInspectorImageDigest:config.runtimeInspectorImageDigest,
        asyncRequest:{id:stored.id,approvalDigest:stored.approvalDigest!}
      },{
        commissionId:stored.commissionId,reviewId:stored.reviewId,
        requestKey:stored.requestKey,operatorApprovalRef:stored.approvalRef,
        operatorSubject:proof.operatorSubject
      });
      return response(
        outcome.state==="reserved"||outcome.state==="uncertain"?202:200,
        outcome
      );
    }
    if(!config.allowLegacyDirectRedrives)return failed(404);
    if(!config.redriveTrust || !config.queue
      || !IMAGE.test(config.runtimeInspectorImageDigest??"")
      || config.runtimeInspectorImageDigest!==config.redriveTrust.requiredImageDigest)
      return failed(503);
    const operation=fields(await jsonBody(request),[
      "commissionId","reviewId","requestKey","operatorApprovalRef"
    ]);
    const proof=await verifyOneShotOperatorAuthorization(config.redriveTrust,{
      accessRequest:request,
      approvalJwt:token(request,"X-Folio-Redrive-Approval-Jws"),
      releaseJwt:token(request,"X-Folio-Inspector-Release-Jws")
    },{
      commissionId:operation.commissionId!,
      reviewId:operation.reviewId!,
      requestKey:operation.requestKey!,
      approvalRef:operation.operatorApprovalRef!
    });
    const outcome=await executeOneShotManualRedrive({
      DB:config.db,
      QUEUE:config.queue,
      authorization:proof,
      requiredInspectorImageDigest:config.runtimeInspectorImageDigest
    },{
      commissionId:operation.commissionId!,
      reviewId:operation.reviewId!,
      requestKey:operation.requestKey!,
      operatorApprovalRef:operation.operatorApprovalRef!,
      operatorSubject:proof.operatorSubject
    });
    return response(
      outcome.state==="reserved"||outcome.state==="uncertain"?202:200,
      outcome
    );
  }catch(error){
    if(error instanceof TooLarge)return failed(413);
    if(error instanceof BadInput || error instanceof ManualRedriveInputError)
      return failed(400);
    if(error instanceof InstitutionalEvidenceDenied)return failed(403);
    if(error instanceof InstitutionalEvidenceUnavailable)return failed(503);
    if(error instanceof AsyncRedriveAccessError
      || error instanceof AsyncRevocationAccessError
      || error instanceof AsyncRevocationDenied
      || error instanceof OperatorAuthorizationError
      || error instanceof RevocationAuthorizationError
      || error instanceof RevocationRegistrationAccessError
      || error instanceof ManualRedriveAccessError) return failed(403);
    if(error instanceof AsyncRedriveConflictError
      || error instanceof AsyncRevocationConflict
      || error instanceof RevocationRegistrationConflictError
      || error instanceof ManualRedriveConflictError)return failed(409);
    // No exception details, JWT claims, subjects or confidential data in response.
    return failed(503);
  }
}
