import { authenticateAccess, type AccessConfig } from "@folio/auth";
import { getCommissionSummary, listAccessibleCommissions, listCommissionBatches, dispatchProcessingOutbox, type ProcessingQueueMessage } from "@folio/data";
import { handleDocumentRequest } from "./document-routes";
import { handleReviewRequest, type ReviewAction } from "./review-routes";
import { handleTransitionRequest } from "./transition-routes";
import { handleObservationDetailRequest } from "./observation-detail";
import { handleReviewExportRequest } from "./review-export-routes";
import { handleReviewableCountRequest } from "./reviewable-count-routes";
import { handleProvisioningRequest } from "./provisioning-routes";
import { handleMemberRequest } from "./member-routes";
import { handleBootstrapRequest } from "./bootstrap-routes";
import { runQuarantineAudit, runProcessingAudit } from "./maintenance";
import { handleTextRequest } from "./text-routes";

export interface ApiEnv extends AccessConfig {
  /** Unset by default. Only the exact verified Access JWT sub may bootstrap. */
  COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT?: string;
  DB?: D1Database;
  DOCUMENTS?: R2Bucket;
  /** Default-deny PDF intake until independently authorized for Release B. */
  DOCUMENT_UPLOADS_ENABLED?: string;
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

  // Readiness is operator-only and scoped to the API/D1 core. It does not
  // certify R2, Queue, inspector, Access MFA configuration, or Preview release.
  const coreReadiness = url.pathname === "/api/readiness/core";
  const bootstrapCapability = url.pathname === "/api/session";
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
  const reviewableCount = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/observations\/reviewable-count$/.exec(url.pathname);
  const observationDetail = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/observations\/([A-Za-z0-9_-]{1,64})$/.exec(url.pathname);
  const textPages = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/documents\/([A-Za-z0-9_-]{1,64})\/pages$/.exec(url.pathname);
  if (!coreReadiness && !bootstrapCapability && !discovery && !batches && !members && !memberRevoke && !checklistProvision && !route && !documents && !review && !transition && !reviewExport && !reviewableCount && !observationDetail && !textPages) return json({ error: "Not found" }, 404);
  if (((bootstrapCapability || route || coreReadiness) && request.method !== "GET")
    || (discovery && request.method !== "GET" && request.method !== "POST")
    || (batches && request.method !== "GET" && request.method !== "POST")) return json({ error: "Method not allowed" }, 405);

  const subject = await authenticateAccess(request, env);
  if (!subject) return json({ error: "Unauthorized" }, 401);
  if (coreReadiness) {
    // A signed Access identity alone is insufficient to inspect deployment health.
    // Fail closed when the operator binding has not been explicitly configured.
    if (!env.COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT
      || subject !== env.COMMISSION_BOOTSTRAP_OPERATOR_SUBJECT) {
      return json({ error: "Forbidden" }, 403);
    }
    if (!env.DB) return json({ error: "Service unavailable" }, 503);
    try {
      // Require manual pilot tables alongside the later admission/revocation
      // guard objects: a D1 schema without checklist or observation storage
      // is not ready for core work. This is NOT a full migration or integrity audit.
      const result = await env.DB.prepare(`
        SELECT COUNT(*) AS found FROM sqlite_master
        WHERE (type='table' AND name IN (
          'commissions','commission_members','document_batches',
          'document_versions','checklist_items','observations','audit_events'
        )) OR (type='view' AND name='processing_redrive_consumer_denials')
          OR (type='trigger' AND name IN (
            'processing_outbox_verified_completion',
            'processing_redrive_consumer_report_authority_guard',
            'processing_redrive_consumer_status_authority_guard',
            'processing_report_active_commission_guard',
            'processing_status_active_commission_guard'
          ))
      `).first<{found:number}>();
      if (result?.found !== 13) return json({ error: "Service unavailable" }, 503);
      return json({ status: "ready", scope: "api-core" }, 200);
    } catch {
      return json({ error: "Service unavailable" }, 503);
    }
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
      if (discovery) {
        const initial = await listAccessibleCommissions(env.DB, subject);
        if (initial.length === 0) return json(initial, 200);
        // The first D1 query can finish before a membership revocation or role
        // change becomes visible to this request. Return only a *fresh* scoped
        // set; do not reuse the earlier rows, identities or role capabilities.
        // One bounded re-read avoids an N+1 authorization check per commission.
        return json(await listAccessibleCommissions(env.DB, subject), 200);
      }
      const summary = await getCommissionSummary(env.DB, subject, batches![1]!);
      if (!summary) return json({ error: "Not found" }, 404);
      const records=await listCommissionBatches(env.DB,subject,batches![1]!);
      // A commission member can be revoked after listCommissionBatches
      // resolves; do not expose a stale batch list after losing access.
      if(!await getCommissionSummary(env.DB,subject,batches![1]!)) {
        return json({error:"Not found"},404);
      }
      return json(records,200);
    } catch { return json({ error: "Request could not be completed" }, 503); }
  }
  if (documents) {
    return handleDocumentRequest(request, {
      DB: env.DB, DOCUMENTS: env.DOCUMENTS,
      DOCUMENT_UPLOADS_ENABLED: env.DOCUMENT_UPLOADS_ENABLED
    }, subject,
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
  // Named route precedes the generic observation/:id matcher.
  if (reviewableCount) return handleReviewableCountRequest(request,{DB:env.DB},subject,reviewableCount[1]!);
  if (observationDetail) return handleObservationDetailRequest(request,{DB:env.DB},subject,observationDetail[1]!,observationDetail[2]!);

  if (!route) return json({ error: "Not found" }, 404);
  try {
    const summary = await getCommissionSummary(env.DB, subject, route[1]!);
    if (!summary) return json({ error: "Not found" }, 404);
    // A scoped row may have been read before a revocation or role change.
    // Return only the current authorized row, without stale capabilities.
    const current = await getCommissionSummary(env.DB, subject, route[1]!);
    return current ? json(current, 200) : json({ error: "Not found" }, 404);
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
