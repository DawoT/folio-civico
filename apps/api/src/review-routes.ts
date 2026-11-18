import {
  getCommissionSummary, listChecklist, listObservationDrafts, persistDraftObservation, findIdempotentDraft,
  ReviewAccessError, ReviewEvidenceError
} from "@folio/data";

export type ReviewAction = "checklist" | "observations" | "drafts";

export interface ReviewEnv { DB: D1Database; }

function json(body: unknown, status: number): Response {
  return Response.json(body, {
    status, headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
  });
}

class RequestError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

const MAX_BODY = 16 * 1024;

async function readInput(request: Request): Promise<Record<string, string>> {
  if (request.headers.get("Content-Type")?.toLowerCase() !== "application/json") {
    throw new RequestError(415, "Only application/json is supported");
  }
  if (Number(request.headers.get("Content-Length") ?? 0) > MAX_BODY) {
    throw new RequestError(413, "Request body too large");
  }
  if (!request.body) throw new RequestError(400, "Missing request body");
  const reader = request.body.getReader();
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > MAX_BODY) {
        await reader.cancel("Limit exceeded");
        throw new RequestError(413, "Request body too large");
      }
      chunks.push(chunk.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let position = 0;
  for (const chunk of chunks) { bytes.set(chunk, position); position += chunk.length; }
  let raw: unknown;
  try { raw = JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)); }
  catch { throw new RequestError(400, "Invalid JSON body"); }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new RequestError(400,"Invalid body");
  const value = raw as Record<string, unknown>;
  const keys = ["title","description","checklistItemId","batchId"];
  if (Object.keys(value).length !== keys.length || Object.keys(value).some((key) => !keys.includes(key))) {
    throw new RequestError(400,"Unexpected request fields");
  }
  if (keys.some((key) => typeof value[key] !== "string")) throw new RequestError(400,"Invalid fields");
  const typed = value as Record<string,string>;
  if (!typed.title?.trim() || typed.title.length > 160
    || !typed.description?.trim() || typed.description.length > 4000
    || !/^[A-Za-z0-9_-]{1,64}$/.test(typed.checklistItemId ?? "")
    || !/^[A-Za-z0-9_-]{1,64}$/.test(typed.batchId ?? "")) {
    throw new RequestError(400, "Invalid observation fields");
  }
  return typed;
}

/** Internal route. subject must have been verified against Access JWT by the API Worker. */
export async function handleReviewRequest(
  request: Request, env: ReviewEnv, subject: string, commissionId: string, action: ReviewAction
): Promise<Response> {
  if ((action === "drafts" && request.method !== "POST")
    || (action !== "drafts" && request.method !== "GET")) {
    return json({error:"Method not allowed"},405);
  }
  try {
    const membership = await getCommissionSummary(env.DB, subject, commissionId);
    if (!membership) return json({error:"Not found"},404);
    if (action === "checklist") return json(await listChecklist(env.DB, subject, commissionId),200);
    if (action === "observations") return json(await listObservationDrafts(env.DB, subject, commissionId),200);
    if (membership.status !== "active") return json({error:"Commission is closed"},409);
    if (membership.role === "observer") return json({error:"Forbidden"},403);

    const origin = request.headers.get("Origin");
    if (origin && origin !== new URL(request.url).origin) return json({error:"Forbidden"},403);
    const key=request.headers.get("Idempotency-Key");
    if (!key || !/^[A-Za-z0-9_-]{8,96}$/.test(key)) {
      return json({error:"Valid Idempotency-Key required"},400);
    }
    const body = await readInput(request);
    const canonical=JSON.stringify([
      body.title!.trim(),body.description!.trim(),body.checklistItemId!,body.batchId!
    ]);
    const bytes=new TextEncoder().encode(canonical);
    const sha=await crypto.subtle.digest("SHA-256",bytes);
    const payloadHash=Array.from(new Uint8Array(sha),b=>b.toString(16).padStart(2,"0")).join("");

    async function existingResponse(): Promise<Response | null> {
      const previous=await findIdempotentDraft(env.DB,subject,commissionId,key!);
      if (!previous) return null;
      if (previous.payloadHash !== payloadHash) return json({error:"Idempotency key already used for another draft"},409);
      return json(previous.observation,200);
    }
    const existing=await existingResponse();
    if (existing) return existing;

    try {
      const saved = await persistDraftObservation(env.DB, {
        commissionId, authorSubject: subject, title: body.title!, description: body.description!,
        evidence: [{
          type:"SEARCH_SCOPE",commissionId,checklistItemId:body.checklistItemId!,
          batchId:body.batchId!, reviewerId:subject,searchedAt:new Date().toISOString()
        }]
      },{key,payloadHash});
      return json(saved,201);
    } catch (error) {
      // A concurrent request may have claimed the same unique key during D1.batch.
      // Requery after the failed transaction, but never hide unrelated failures.
      if (!(error instanceof ReviewAccessError) && !(error instanceof ReviewEvidenceError)) {
        const concurrent=await existingResponse();
        if (concurrent) return concurrent;
      }
      throw error;
    }
  } catch (error) {
    if (error instanceof RequestError) return json({error:error.message},error.status);
    if (error instanceof ReviewEvidenceError) return json({error:"Evidence is not available in this commission"},422);
    if (error instanceof ReviewAccessError) return json({error:"Forbidden"},403);
    return json({error:"Request could not be completed"},503);
  }
}
