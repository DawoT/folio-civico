import { describe, expect, it } from "vitest";
import { PdfValidationError, readPdfUpload, MAX_PDF_BYTES } from "./pdf";

const pdf = new TextEncoder().encode("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF");
function request(bytes: Uint8Array, headers: Record<string, string> = {}) {
  return new Request("https://folio.test/upload", {
    method: "POST", headers: {
      "Content-Type": "application/pdf",
      "X-Document-Filename": encodeURIComponent("Contrato de obra.pdf"),
      "Idempotency-Key": "upload_req_123",
      ...headers
    }, body: bytes as BodyInit
  });
}

describe("PDF quarantine intake", () => {
  it("accepts a PDF, derives SHA-256 and sanitizes its filename", async () => {
    const result = await readPdfUpload(request(pdf));
    expect(result.filename).toBe("Contrato de obra.pdf");
    expect(result.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.bytes.byteLength).toBe(pdf.byteLength);
    expect(result.idempotencyKey).toBe("upload_req_123");
  });

  it.each([
    ["unexpected mime", { "Content-Type": "application/octet-stream" }, pdf, 415],
    ["declared too large", { "Content-Length": String(MAX_PDF_BYTES + 1) }, pdf, 413],
    ["bad file extension", { "X-Document-Filename": "contract.txt" }, pdf, 400],
    ["path traversal", { "X-Document-Filename": "a%2Fcontract.pdf" }, pdf, 400],
    ["invalid key", { "Idempotency-Key": "x" }, pdf, 400],
    ["spoofed pdf", {}, new TextEncoder().encode("<script>test</script>"), 422]
  ])("rejects %s", async (_label, headers, bytes, status) => {
    try {
      await readPdfUpload(request(bytes, headers));
      throw new Error("validation unexpectedly accepted");
    } catch (error) {
      expect(error).toBeInstanceOf(PdfValidationError);
      expect((error as PdfValidationError).status).toBe(status);
    }
  });

  it("rejects a stream exceeding the cap even without Content-Length", async () => {
    const source = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("%PDF-1.7\n"));
        controller.enqueue(new Uint8Array(MAX_PDF_BYTES));
        controller.close();
      }
    });
    const upload = new Request("https://folio.test/upload", {
      method: "POST", body: source,
      headers: { "Content-Type": "application/pdf", "X-Document-Filename": "work.pdf", "Idempotency-Key": "upload_big_001" },
      duplex: "half"
    } as RequestInit);
    await expect(readPdfUpload(upload)).rejects.toMatchObject({ status: 413 });
  });
});
