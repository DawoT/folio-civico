/** MVP intake cap: intentionally conservative until scanning and streaming OCR are ready. */
export const MAX_PDF_BYTES = 8 * 1024 * 1024;

export class PdfValidationError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "PdfValidationError";
  }
}

export interface ValidatedPdf {
  bytes: Uint8Array;
  sha256: string;
  filename: string;
  idempotencyKey: string;
}

function cleanFilename(request: Request): string {
  const encoded = request.headers.get("X-Document-Filename");
  if (!encoded) throw new PdfValidationError(400, "Missing document filename");
  let filename: string;
  try {
    filename = decodeURIComponent(encoded);
  } catch {
    throw new PdfValidationError(400, "Invalid filename encoding");
  }
  if (!filename || filename.length > 160 || filename.trim() !== filename
    || !/\.pdf$/i.test(filename)
    || /[\\/\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(filename)
    || filename.startsWith(".")) {
    throw new PdfValidationError(400, "Invalid PDF filename");
  }
  return filename;
}

/** Read no more than MAX_PDF_BYTES even for chunked requests with no size header. */
export async function readPdfUpload(request: Request): Promise<ValidatedPdf> {
  if (request.headers.get("Content-Type")?.toLowerCase() !== "application/pdf") {
    throw new PdfValidationError(415, "Only application/pdf is supported");
  }
  const filename = cleanFilename(request);
  const idempotencyKey = request.headers.get("Idempotency-Key");
  if (!idempotencyKey || !/^[a-zA-Z0-9_-]{8,96}$/.test(idempotencyKey)) {
    throw new PdfValidationError(400, "Valid Idempotency-Key required");
  }
  const declared = request.headers.get("Content-Length");
  if (declared !== null) {
    if (!/^\d+$/.test(declared) || !Number.isSafeInteger(Number(declared))) {
      throw new PdfValidationError(400, "Invalid declared length");
    }
    if (Number(declared) > MAX_PDF_BYTES) {
      throw new PdfValidationError(413, "PDF exceeds the upload limit");
    }
  }

  if (!request.body) throw new PdfValidationError(400, "Empty upload body");

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_PDF_BYTES) {
        await reader.cancel("Upload limit exceeded");
        throw new PdfValidationError(413, "PDF exceeds the upload limit");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof PdfValidationError) throw error;
    throw new PdfValidationError(400, "Unable to read request body");
  } finally {
    reader.releaseLock();
  }

  if (total === 0) throw new PdfValidationError(422, "Empty PDF");
  if (declared !== null && Number(declared) !== total) {
    throw new PdfValidationError(400, "Declared upload size does not match");
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  // Signature validation alone does not make a PDF safe; it remains quarantined.
  const header = new TextDecoder("ascii").decode(bytes.subarray(0, 8));
  if (!/^%PDF-[12]\.\d/.test(header)) {
    throw new PdfValidationError(422, "Invalid PDF signature");
  }

  const digest = await crypto.subtle.digest("SHA-256", bytes.buffer);
  const sha256 = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
  return { bytes, sha256, filename, idempotencyKey };
}
