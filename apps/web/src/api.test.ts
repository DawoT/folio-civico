import { describe, expect, it, vi } from "vitest";
import { makeDocumentsPath, loadDocuments, uploadPdf, ApiError } from "./api";

describe("document API client", () => {
  it("builds a scoped, encoded path and rejects invalid tenant IDs", () => {
    expect(makeDocumentsPath("com_1", "batch_2")).toBe("/api/commissions/com_1/batches/batch_2/documents");
    expect(() => makeDocumentsPath("../other", "batch_2")).toThrow();
  });

  it("loads a tenant-scoped document list without storing it", async () => {
    const fetcher=vi.fn(async()=>Response.json([{id:"doc_1",filename:"Contrato.pdf"}]));
    const result=await loadDocuments({commissionId:"com_1",batchId:"batch_2"},fetcher);
    expect(result).toHaveLength(1);
    expect(fetcher).toHaveBeenCalledWith(
      "/api/commissions/com_1/batches/batch_2/documents",
      expect.objectContaining({credentials:"same-origin",cache:"no-store"})
    );
  });

  it("rejects unauthorized access without treating it as an empty list", async () => {
    const fetcher=vi.fn(async()=>Response.json({error:"Unauthorized"},{status:401}));
    await expect(loadDocuments({commissionId:"com_1",batchId:"batch_2"},fetcher))
      .rejects.toMatchObject({status:401});
  });

  it("sends an idempotent PDF upload with same-origin credentials", async () => {
    const fetcher=vi.fn(async (_input: RequestInfo | URL, _options?: RequestInit) => Response.json({documentId:"doc_1",ingestStatus:"quarantined"},{status:201}));
    const file=new File([new TextEncoder().encode("%PDF-1.7\n")],"Contrato.pdf",{type:"application/pdf"});
    const result=await uploadPdf({commissionId:"com_1",batchId:"batch_2"},file,fetcher,()=> "upload_req_123");
    expect(result).toMatchObject({documentId:"doc_1",ingestStatus:"quarantined"});
    const [,options] = fetcher.mock.calls[0] ?? [];
    expect(options).toMatchObject({method:"POST",credentials:"same-origin",cache:"no-store"});
    expect(options?.headers).toMatchObject({
      "Content-Type":"application/pdf", "X-Document-Filename":"Contrato.pdf",
      "Idempotency-Key":"upload_req_123"
    });
  });

  it("retains the updated processing status in an idempotent upload response",async()=>{
    const fetcher=vi.fn(async()=>Response.json({
      documentId:"doc_1",versionId:"ver_1",sha256:"a".repeat(64),
      ingestStatus:"quarantined",processingStatus:"ready",repeated:true
    },{status:200}));
    const file=new File([new TextEncoder().encode("%PDF-1.7\n1 0 obj\n%%EOF")],
      "Contrato.pdf",{type:"application/pdf"});
    expect(await uploadPdf({
      commissionId:"com_1",batchId:"batch_2"
    },file,fetcher,()=> "upload_req_123")).toMatchObject({
      documentId:"doc_1",processingStatus:"ready",repeated:true
    });
  });

  it("blocks non-PDF or oversized uploads before sending", async () => {
    const fetcher=vi.fn();
    const text=new File(["text"],"note.txt",{type:"text/plain"});
    await expect(uploadPdf({commissionId:"com_1",batchId:"batch_2"},text,fetcher)).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).not.toHaveBeenCalled();
  });
});
