import { authenticateAccess, type AccessConfig } from "@folio/auth";
import { getCommissionSummary, listAccessibleCommissions, listCommissionBatches, dispatchProcessingOutbox, type ProcessingQueueMessage } from "@folio/data";
import { handleDocumentRequest } from "./document-routes";
import { handleReviewRequest, type ReviewAction } from "./review-routes";
import { handleTransitionRequest } from "./transition-routes";
import { runQuarantineAudit } from "./maintenance";
import { handleTextRequest } from "./text-routes";

export interface ApiEnv extends AccessConfig {
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

  const discovery = url.pathname === "/api/commissions";
  const batches = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/batches$/.exec(url.pathname);
  const route = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/summary$/.exec(url.pathname);
  const documents = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/batches\/([A-Za-z0-9_-]{1,64})\/documents$/.exec(url.pathname);
  const review = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/(checklist|observations|observations\/drafts|observations\/page-drafts)$/.exec(url.pathname);
  const transition = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/observations\/([A-Za-z0-9_-]{1,64})\/actions$/.exec(url.pathname);
  const textPages = /^\/api\/commissions\/([A-Za-z0-9_-]{1,64})\/documents\/([A-Za-z0-9_-]{1,64})\/pages$/.exec(url.pathname);
  if (!discovery && !batches && !route && !documents && !review && !transition && !textPages) return json({ error: "Not found" }, 404);
  if ((discovery || batches || route) && request.method !== "GET") return json({ error: "Method not allowed" }, 405);

  const subject = await authenticateAccess(request, env);
  if (!subject) return json({ error: "Unauthorized" }, 401);
  if (!env.DB) return json({ error: "Service not configured" }, 503);
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
      : review[2] === "observations" ? "observations" : "checklist";
    return handleReviewRequest(request, {DB:env.DB},subject,review[1]!,action);
  }

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
    // Dormant by default: neither a cron nor a Queue binding exists in Wrangler.
    if (env.PROCESSING_QUEUE && env.DB) {
      ctx.waitUntil(dispatchProcessingOutbox(env.DB, env.PROCESSING_QUEUE)
        .then(stats => { console.log(JSON.stringify({kind:"folio.processing.outbox",...stats})); }));
    }
  }
} satisfies ExportedHandler<ApiEnv>;
