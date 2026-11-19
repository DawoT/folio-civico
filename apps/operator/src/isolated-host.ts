import {
  verifyRevocationAuthorization,RevocationAuthorizationError,
  verifyOneShotOperatorAuthorization,OperatorAuthorizationError,
  type RevocationScope,type RevocationAuthorizationConfig,
  type OperatorPreflightConfig
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

/**
 * R2.9: a synthetic-only private HTTP adapter, not a Cloudflare Worker.
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
  redriveTrust?:OperatorPreflightConfig;
  /** Injected fake Queue in local tests; NEVER a live binding here. */
  queue?:{send(message:ProcessingQueueMessage):Promise<unknown>};
  /** Trusted image identity, never from a client-supplied JSON body. */
  runtimeInspectorImageDigest?:string;
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
      || ![PATH+"revocations",PATH+"redrives"].includes(url.pathname))
      return failed(404);
    if(request.method!=="POST")return failed(405);
    if(forbiddenBrowserRequest(request))return failed(403);
    if(!/^application\/json(?:;\s*charset=utf-8)?$/i.test(
      request.headers.get("Content-Type")??""
    ))return failed(415);

    if(url.pathname===PATH+"revocations"){
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
    if(error instanceof OperatorAuthorizationError
      || error instanceof RevocationAuthorizationError
      || error instanceof RevocationRegistrationAccessError
      || error instanceof ManualRedriveAccessError) return failed(403);
    if(error instanceof RevocationRegistrationConflictError
      || error instanceof ManualRedriveConflictError)return failed(409);
    // No exception details, JWT claims, subjects or confidential data in response.
    return failed(503);
  }
}
