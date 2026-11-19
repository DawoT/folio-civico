export interface Scope {
  commissionId: string;
  batchId: string;
}

export interface DocumentTextPage { page:number; text:string }
export interface DocumentTextView {
  versionId:string;
  sha256:string;
  pageCount:number;
  pages:DocumentTextPage[];
}
export async function loadDocumentText(
  commissionId:string,versionId:string,fetcher:typeof fetch=fetch
):Promise<DocumentTextView> {
  if(!validId.test(commissionId) || !validId.test(versionId)) {
    throw new ApiError(400,"Identificador del documento no válido.");
  }
  const response=await fetcher(`/api/commissions/${commissionId}/documents/${versionId}/pages`,{
    credentials:"same-origin",cache:"no-store"
  });
  const body=await expectJson(response);
  if(!body || typeof body!=="object" || !Array.isArray((body as DocumentTextView).pages)) {
    throw new ApiError(502,"Respuesta de páginas inválida.");
  }
  return body as DocumentTextView;
}

export interface DocumentRow {
  id: string;
  filename: string;
  versionId: string;
  sha256: string;
  extractionStatus: "pending" | "processing" | "ready" | "needs_review" | "failed";
  pageCount: number | null;
  createdAt: string;
}

export interface UploadResult {
  documentId: string;
  versionId: string;
  sha256: string;
  ingestStatus: "quarantined";
  processingStatus: "pending";
  repeated: boolean;
}

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

const maxBytes = 8 * 1024 * 1024;
const validId = /^[a-zA-Z0-9_-]{1,64}$/;

export function makeDocumentsPath(commissionId: string, batchId: string): string {
  if (!validId.test(commissionId) || !validId.test(batchId)) {
    throw new ApiError(400, "Los identificadores de comisión y lote no son válidos.");
  }
  return `/api/commissions/${commissionId}/batches/${batchId}/documents`;
}

async function expectJson(response: Response): Promise<unknown> {
  if (!response.ok) {
    const messages: Record<number, string> = {
      400:"La solicitud no es válida.",
      401:"No hay una sesión válida de Cloudflare Access.",
      403:"Tu usuario no tiene permiso para esta operación.",
      404:"La comisión o el lote no se encuentra dentro de tu acceso.",
      409:"La clave de carga ya pertenece a otro archivo, o la comisión está cerrada.",
      413:"El PDF supera el máximo de 8 MiB.",
      415:"Solo se admiten archivos PDF.",
      422:"El archivo no tiene una firma PDF válida.",
      503:"El servicio no está disponible. Inténtalo de nuevo."
    };
    throw new ApiError(response.status, messages[response.status] ?? "No se pudo completar la solicitud.");
  }
  return response.json();
}

export async function loadDocuments(scope: Scope, fetcher: typeof fetch = fetch): Promise<DocumentRow[]> {
  const response = await fetcher(makeDocumentsPath(scope.commissionId, scope.batchId), {
    credentials: "same-origin",
    cache: "no-store"
  });
  const body = await expectJson(response);
  if (!Array.isArray(body)) throw new ApiError(502, "Respuesta inesperada de documentos.");
  return body as DocumentRow[];
}

export async function uploadPdf(
  scope: Scope, file: File, fetcher: typeof fetch = fetch,
  makeKey: () => string = () => crypto.randomUUID()
): Promise<UploadResult> {
  const path = makeDocumentsPath(scope.commissionId, scope.batchId);
  if (!/\.pdf$/i.test(file.name) || (file.type && file.type !== "application/pdf")) {
    throw new ApiError(415, "Solo se admiten archivos PDF.");
  }
  if (file.size === 0 || file.size > maxBytes) {
    throw new ApiError(413, "El archivo debe tener entre 1 byte y 8 MiB.");
  }
  const response = await fetcher(path, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      "Content-Type": "application/pdf",
      "X-Document-Filename": encodeURIComponent(file.name),
      "Idempotency-Key": makeKey()
    },
    body: file
  });
  return await expectJson(response) as UploadResult;
}


export interface Commission {
  id: string;
  name: string;
  status: "active" | "closed";
  role: "president" | "member" | "advisor" | "observer";
}
export interface CommissionBatch {
  id: string;
  label: string;
}
export async function loadCommissions(fetcher: typeof fetch = fetch): Promise<Commission[]> {
  const response = await fetcher("/api/commissions", {
    credentials:"same-origin", cache:"no-store"
  });
  const body = await expectJson(response);
  if (!Array.isArray(body)) throw new ApiError(502, "Respuesta inesperada de comisiones.");
  return body as Commission[];
}
export async function loadCommissionBatches(
  commissionId: string, fetcher: typeof fetch = fetch
): Promise<CommissionBatch[]> {
  if (!validId.test(commissionId)) throw new ApiError(400, "Identificador de comisión no válido.");
  const response = await fetcher(`/api/commissions/${commissionId}/batches`, {
    credentials:"same-origin", cache:"no-store"
  });
  const body = await expectJson(response);
  if (!Array.isArray(body)) throw new ApiError(502, "Respuesta inesperada de lotes.");
  return body as CommissionBatch[];
}


export interface ChecklistRow {
  id: string;
  area: "works" | "procurement";
  expectedDocument: string;
  status: "pending" | "located" | "not_located" | "observed";
  reviewedBy: string | null;
  reviewedAt: string | null;
}

export interface ObservationEvidence {
  type: "SEARCH_SCOPE" | "DOCUMENT_PAGE" | "OFFICIAL_SOURCE";
  commissionId: string;
  [key: string]: unknown;
}

export interface ObservationRow {
  id: string;
  commissionId: string;
  authorSubject: string;
  title: string;
  description: string;
  status: "draft" | "in_review" | "validated" | "dismissed";
  validatedBy: string | null;
  createdAt: string;
  evidence: ObservationEvidence[];
  canSubmit?: boolean;
  canReview?: boolean;
  reviewedBy?: string | null;
  reviewedAt?: string | null;
  reviewNote?: string | null;
}

export interface SearchScopeDraftInput {
  commissionId: string;
  checklistItemId: string;
  batchId: string;
  title: string;
  description: string;
}

function commissionPath(commissionId: string): string {
  if (!validId.test(commissionId)) throw new ApiError(400,"Identificador de comisión no válido.");
  return `/api/commissions/${commissionId}`;
}

export async function loadChecklist(commissionId: string, fetcher: typeof fetch = fetch): Promise<ChecklistRow[]> {
  const response = await fetcher(commissionPath(commissionId)+"/checklist", {
    credentials:"same-origin",cache:"no-store"
  });
  const body=await expectJson(response);
  if (!Array.isArray(body)) throw new ApiError(502,"Respuesta inesperada del checklist.");
  return body as ChecklistRow[];
}

export async function loadObservationDrafts(
  commissionId: string, fetcher: typeof fetch = fetch
): Promise<ObservationRow[]> {
  const response = await fetcher(commissionPath(commissionId)+"/observations", {
    credentials:"same-origin",cache:"no-store"
  });
  const body=await expectJson(response);
  if (!Array.isArray(body)) throw new ApiError(502,"Respuesta inesperada de las observaciones.");
  return body as ObservationRow[];
}

export interface ObservationTransitionInput {
  commissionId: string;
  observationId: string;
  action: "submit" | "validate" | "dismiss";
  note?: string;
}
export async function transitionObservation(
  input: ObservationTransitionInput,
  fetcher: typeof fetch = fetch,
  makeKey: () => string = () => crypto.randomUUID()
): Promise<ObservationRow & {replayed:boolean}> {
  if (!validId.test(input.observationId)) throw new ApiError(400,"Identificador de observación no válido.");
  if(input.action !== "submit"
    && (!input.note?.trim() || input.note.trim().length<15 || input.note.length>1000)) {
    throw new ApiError(400,"La decisión requiere una justificación de al menos 15 caracteres.");
  }
  const path=commissionPath(input.commissionId)+`/observations/${input.observationId}/actions`;
  const body=input.action==="submit" ? {action:input.action}
    : {action:input.action,note:input.note?.trim()};
  const response=await fetcher(path,{
    method:"POST",credentials:"same-origin",cache:"no-store",
    headers:{"Content-Type":"application/json","Idempotency-Key":makeKey()},
    body:JSON.stringify(body)
  });
  return await expectJson(response) as ObservationRow & {replayed:boolean};
}

export async function submitSearchScopeDraft(
  input: SearchScopeDraftInput, fetcher: typeof fetch = fetch,
  makeKey: () => string = () => crypto.randomUUID()
): Promise<ObservationRow> {
  if (!validId.test(input.batchId) || !validId.test(input.checklistItemId)
    || !input.title.trim() || input.title.length > 160
    || !input.description.trim() || input.description.length > 4000) {
    throw new ApiError(400,"Completa una búsqueda documental válida.");
  }
  const response = await fetcher(commissionPath(input.commissionId)+"/observations/drafts", {
    method:"POST",credentials:"same-origin",cache:"no-store",
    headers:{"Content-Type":"application/json","Idempotency-Key":makeKey()},
    body:JSON.stringify({
      title:input.title,
      description:input.description,
      checklistItemId:input.checklistItemId,
      batchId:input.batchId
    })
  });
  return await expectJson(response) as ObservationRow;
}


export interface DocumentPageDraftInput {
  commissionId:string;
  documentVersionId:string;
  page:number;
  title:string;
  description:string;
}
export async function submitDocumentPageDraft(
  input:DocumentPageDraftInput,
  fetcher:typeof fetch=fetch,
  makeKey:()=>string=()=>crypto.randomUUID()
):Promise<ObservationRow>{
  if(!validId.test(input.commissionId) || !validId.test(input.documentVersionId)
    || !Number.isSafeInteger(input.page) || input.page<1 || input.page>100
    || !input.title.trim() || input.title.length>160
    || !input.description.trim() || input.description.length>4000) {
    throw new ApiError(400,"Completa una referencia de página válida.");
  }
  const response=await fetcher(commissionPath(input.commissionId)+"/observations/page-drafts",{
    method:"POST",credentials:"same-origin",cache:"no-store",
    headers:{"Content-Type":"application/json","Idempotency-Key":makeKey()},
    body:JSON.stringify({
      title:input.title,description:input.description,
      documentVersionId:input.documentVersionId,page:input.page
    })
  });
  return await expectJson(response) as ObservationRow;
}
