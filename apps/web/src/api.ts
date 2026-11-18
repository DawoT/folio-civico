export interface Scope {
  commissionId: string;
  batchId: string;
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
