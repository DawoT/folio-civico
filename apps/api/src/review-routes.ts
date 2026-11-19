import {
  getCommissionSummary, getDocumentTextPages,
  listChecklist, listObservationDrafts, listObservationPage, ObservationCursorError,
  persistDraftObservation, findIdempotentDraft,
  ReviewAccessError, ReviewEvidenceError
} from "@folio/data";
import type { Evidence } from "@folio/domain";

export type ReviewAction = "checklist" | "observations" | "history" | "drafts" | "page-drafts";

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
type DraftInput={
  title:string;description:string;
  checklistItemId?:string;batchId?:string;
  documentVersionId?:string;page?:number
};

async function readInput(request: Request, kind:"search"|"page"): Promise<DraftInput> {
  if (request.headers.get("Content-Type")?.toLowerCase() !== "application/json") {
    throw new RequestError(415, "Only application/json is supported");
  }
  const declared=request.headers.get("Content-Length");
  if(declared && (!/^\d+$/.test(declared) || Number(declared)>MAX_BODY)) {
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
  const fields=kind==="search"
    ? ["title","description","checklistItemId","batchId"]
    : ["title","description","documentVersionId","page"];
  if(Object.keys(value).length!==fields.length
    || Object.keys(value).some(k=>!fields.includes(k))) {
    throw new RequestError(400,"Unexpected request fields");
  }
  if(typeof value.title!=="string" || !value.title.trim() || value.title.length>160
    || typeof value.description!=="string" || !value.description.trim()
    || value.description.length>4000) {
    throw new RequestError(400,"Invalid observation text");
  }
  const body:DraftInput={title:value.title,description:value.description};
  if(kind==="search") {
    if(typeof value.checklistItemId!=="string"
      || !/^[A-Za-z0-9_-]{1,64}$/.test(value.checklistItemId)
      || typeof value.batchId!=="string"
      || !/^[A-Za-z0-9_-]{1,64}$/.test(value.batchId)) {
      throw new RequestError(400,"Invalid search scope");
    }
    body.checklistItemId=value.checklistItemId;
    body.batchId=value.batchId;
  } else {
    if(typeof value.documentVersionId!=="string"
      || !/^[A-Za-z0-9_-]{1,64}$/.test(value.documentVersionId)
      || !Number.isSafeInteger(value.page)
      || (value.page as number)<1 || (value.page as number)>100) {
      throw new RequestError(400,"Invalid page citation");
    }
    body.documentVersionId=value.documentVersionId;
    body.page=value.page as number;
  }
  return body;
}

/** Internal route. subject must have been verified against Access JWT by the API Worker. */
export async function handleReviewRequest(
  request: Request, env: ReviewEnv, subject: string, commissionId: string, action: ReviewAction
): Promise<Response> {
  const isDraft=action==="drafts" || action==="page-drafts";
  if ((isDraft && request.method !== "POST")
    || (!isDraft && request.method !== "GET")) {
    return json({error:"Method not allowed"},405);
  }
  try {
    const membership = await getCommissionSummary(env.DB, subject, commissionId);
    if (!membership) return json({error:"Not found"},404);
    if (action === "checklist") return json(await listChecklist(env.DB, subject, commissionId),200);
    if (action === "observations") return json(await listObservationDrafts(env.DB, subject, commissionId),200);
    if (action === "history") {
      const params=new URL(request.url).searchParams;
      if ([...params.keys()].some(key=>key!=="cursor" && key!=="limit")
        || params.getAll("cursor").length>1 || params.getAll("limit").length>1) {
        return json({error:"Unsupported history filters"},400);
      }
      const rawLimit=params.get("limit");
      if(rawLimit!==null && !/^(?:[1-9]|[1-4][0-9]|50)$/.test(rawLimit)) {
        return json({error:"Invalid history page size"},400);
      }
      const rawCursor=params.get("cursor");
      if(rawCursor!==null && rawCursor.length===0) {
        return json({error:"Invalid history cursor"},400);
      }
      const page=await listObservationPage(env.DB,subject,commissionId,{
        limit:rawLimit===null?25:Number(rawLimit),cursor:rawCursor
      });
      return json(page,200);
    }
    if (membership.status !== "active") return json({error:"Commission is closed"},409);
    if (membership.role === "observer") return json({error:"Forbidden"},403);

    const origin = request.headers.get("Origin");
    if (origin && origin !== new URL(request.url).origin) return json({error:"Forbidden"},403);
    const key=request.headers.get("Idempotency-Key");
    if (!key || !/^[A-Za-z0-9_-]{8,96}$/.test(key)) {
      return json({error:"Valid Idempotency-Key required"},400);
    }
    const kind=action==="page-drafts"?"page":"search";
    const body=await readInput(request,kind);
    const canonical=kind==="page"
      ? JSON.stringify(["PAGE",body.title.trim(),body.description.trim(),body.documentVersionId,body.page])
      : JSON.stringify([body.title.trim(),body.description.trim(),body.checklistItemId,body.batchId]);
    const sha=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(canonical));
    const payloadHash=Array.from(new Uint8Array(sha),b=>b.toString(16).padStart(2,"0")).join("");

    async function existingResponse(): Promise<Response | null> {
      const previous=await findIdempotentDraft(env.DB,subject,commissionId,key!);
      if (!previous) return null;
      if (previous.payloadHash !== payloadHash) return json({error:"Idempotency key already used for another draft"},409);
      return json(previous.observation,200);
    }
    const existing=await existingResponse();
    if (existing) return existing;

    let evidence:Evidence;
    if(kind==="search") {
      evidence={
        type:"SEARCH_SCOPE",commissionId,checklistItemId:body.checklistItemId!,
        batchId:body.batchId!,reviewerId:subject,searchedAt:new Date().toISOString()
      };
    } else {
      const ready=await getDocumentTextPages(env.DB,subject,commissionId,body.documentVersionId!);
      if(!ready || !ready.pages.some(p=>p.page===body.page)) {
        return json({error:"Page has not passed the trusted processing gate"},422);
      }
      evidence={
        type:"DOCUMENT_PAGE",commissionId,documentVersionId:body.documentVersionId!,
        page:body.page!,sha256:ready.sha256
      };
    }
    try {
      const saved = await persistDraftObservation(env.DB, {
        commissionId, authorSubject: subject, title: body.title, description: body.description,
        evidence:[evidence]
      },{key,payloadHash});
      return json(saved,201);
    } catch (error) {
      // A concurrent request may have claimed the same unique key during D1.batch.
      if (!(error instanceof ReviewAccessError) && !(error instanceof ReviewEvidenceError)) {
        const concurrent=await existingResponse();
        if (concurrent) return concurrent;
      }
      throw error;
    }
  } catch (error) {
    if (error instanceof RequestError) return json({error:error.message},error.status);
    if (error instanceof ObservationCursorError) return json({error:"Invalid history pagination"},400);
    if (error instanceof ReviewEvidenceError) return json({error:"Evidence is not available in this commission"},422);
    if (error instanceof ReviewAccessError) return json({error:"Forbidden"},403);
    return json({error:"Request could not be completed"},503);
  }
}
