import { authenticateAccess, type AccessConfig } from "@folio/auth";
import { getCommissionSummary, listAccessibleCommissions, listCommissionBatches, dispatchProcessingOutbox, type ProcessingQueueMessage } from "@folio/data";
import { handleDocumentRequest } from "./document-routes";
import { handleReviewRequest, type ReviewAction } from "./review-routes";
import { handleTransitionRequest } from "./transition-routes";
import { handleObservationDetailRequest } from "./observation-detail";
import { handleReviewExportRequest } from "./review-export-routes";
import { handleProvisioningRequest } from "./provisioning-routes";
import { handleMemberRequest } from "./member-routes";
import { handleBootstrapRequest } from "./bootstrap-routes";
import { runQuarantineAudit, runProcessingAudit } from "./maintenance";
import { handleTextRequest } from "./text-routes";
import { handleStorageReadiness } from "./readiness";

export interface ApiEnv extends AccessConfig {
  /** Unset by default. Only the exact verified Access JWT sub may bootstrap. */
  COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT?: string;
  /** Separate operator identity for read-only storage readiness; unset by default. */
  READINESS_OPERATOR_SUBJECT?: string;
  DB?: D1Database;
  DOCUMENTS?: R2Bucket;
  /** Optional until operator configures an isolated Folio Cívico Queue. */
  PROCESSING_QUEUE?: Queue<ProcessingQueueMessage>;
}

function json(body: unknown, status: number): Response {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
  });
}

export async function handleApiRequest(request: Request, env: ApiEnv): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/health" && request.method === "GET") {
    return json({ status: "ok" }, 200);
  }

  const bootstrapCapability = url.pathname === "/api/session";
  const readiness = url.pathname === "/api/internal/readiness";
  const discovery = url.pathname === "/api/commissions";
  const batches = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/batches$/.exec(url.pathname);
  const memberRevoke = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/members\/revoke$/.exec(url.pathname);
  const members = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/members$/.exec(url.pathname);
  const checklistProvision = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/checklist\/items$/.exec(url.pathname);
  const route = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/summary$/.exec(url.pathname);
  const documents = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/batches\/([A-Za-z0-9_-]{1,64})\/documents$/.exec(url.pathname);
  const review = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/(checklist|observations|observations\/history|observations\/drafts|observations\/page-drafts)$/.exec(url.pathname);
  const transition = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/observations\/([A-Za-z0-9_-]{1,64})\/actions$/.exec(url.pathname);
  const reviewExport = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/observations\/export$/.exec(url.pathname);
  const observationDetail = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/observations\/([A-Za-z0-9_-]{1,64})$/.exec(url.pathname);
  const textPages = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/documents\/([A-Za-z0-9_-]{1,64})\/pages$/.exec(url.pathname);
  if (!bootstrapCapability && !readiness && !discovery && !batches && !members && !memberRevoke && !checklistProvision && !route && !documents && !review && !transition && !reviewExport && !observationDetail && !textPages) return json({ error: "Not found" }, 404);
  if (((bootstrapCapability || route || readiness) && request.method !== "GET")
    || (discovery && request.method !== "GET" && request.method !== "POST")
    || (batches && request.method !== "GET" && request.method !== "POST")) return json({ error: "Method not allowed" }, 405);

  const subject = await authenticateAccess(request, env);
  if (!subject) return json({ error: "Unauthorized" }, 401);
  if (readiness) {
    if (!env.READINESS_OPERATOR_SUBJECT || env.READINESS_OPERATOR_SUBJECT !== subject) {
      return json({ error: "Not found" }, 404);
    }
    const origin=request.headers.get("Origin");
    if(origin && origin!==url.origin) return json({error:"Forbidden"},403);
    return handleStorageReadiness(env);
  }
  if (!env.DB) return json({ error: "Service not configured" }, 503);
  if (bootstrapCapability) return handleBootstrapRequest(request,{DB:env.DB,operatorSubject:env.COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT},subject,"capability");
  if (discovery && request.method === "POST") return handleBootstrapRequest(request,{DB:env.DB,operatorSubject:env.COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT},subject,"create");
  if (memberRevoke) return handleMemberRequest(request,{DB:env.DB},subject,memberRevoke[1]!,"revoke");
  if (members) return handleMemberRequest(request,{DB:env.DB},subject,members[1]!,"members");
  if (batches && request.method === "POST") return handleProvisioningRequest(request,{DB:env.DB},subject,batches[1]!,"batch");
  if (checklistProvision) return handleProvisioningRequest(request,{DB:env.DB},subject,checklistProvision[1]!,"checklist");
  if (discovery || batches) {
    try {
      if (discovery) return json(await listAccessibleCommissions(env.DB, subject), 200);
      const summary = await getCommissionSummary(env.DB, subject, batches![1]!);
      if (!summary) return json({ error: "Not found" }, 404);
      return json(await listCommissionBatches(env.DB, subject, batches![1]!), 200);
    } catch { return json({ error: "Request could not be completed" }, 503); }
  }
  if (documents) {
    return handleDocumentRequest(request, { DB: env.DB, DOCUMENTS: env.DOCUMENTS }, subject,
      documents[1]!, documents[2]!);
  }
  if (textPages) return handleTextRequest(request,{DB:env.DB},subject,textPages[1]!,textPages[2]!);
  if (transition) return handleTransitionRequest(request,{DB:env.DB},subject,transition[1]!,transition[2]!);
  if (review) {
    const action: ReviewAction = review[2] === "observations/page-drafts" ? "page-drafts" : review[2] === "observations/drafts" ? "drafts"
      : review[2] === "observations/history" ? "history"
      : review[2] === "observations" ? "observations" : "checklist";
    return handleReviewRequest(request, {DB:env.DB},subject,review[1]!,action);
  }
  if (reviewExport) return handleReviewExportRequest(request,{DB:env.DB},subject,reviewExport[1]!);
  if (observationDetail) return handleObservationDetailRequest(request,{DB:env.DB},subject,observationDetail[1]!,observationDetail[2]!);

  if (!route) return json({ error: "Not found" }, 404);
  try {
    const summary = await getCommissionSummary(env.DB, subject, route[1]!);
    // Same response for nonexistent and unauthorized resources.
    return summary ? json(summary, 200) : json({ error: "Not found" }, 404);
  } catch {
    return json({ error: "Request could not be completed" }, 503);
  }
}

export default {
  fetch(request: Request, env: ApiEnv) {
    return handleApiRequest(request, env);
  },
  scheduled(_controller: ScheduledController, env: ApiEnv, ctx: ExecutionContext) {
    // Dormant by default: no cron trigger exists in wrangler.jsonc.
    ctx.waitUntil(runQuarantineAudit(env, (summary) => {
      console.log(JSON.stringify(summary));
    }).then(() => undefined));
    if (env.DB) {
      ctx.waitUntil(runProcessingAudit(env, (summary) => {
        console.log(JSON.stringify(summary));
      }).then(() => undefined));
    }
    // Dormant by default: neither a cron nor a Queue binding exists in Wrangler.
    if (env.PROCESSING_QUEUE && env.DB) {
      ctx.waitUntil(dispatchProcessingOutbox(env.DB, env.PROCESSING_QUEUE)
        .then(stats => { console.log(JSON.stringify({kind:"folio.processing.outbox",...stats})); }));
    }
  }
} satisfies ExportedHandler<ApiEnv>;
