import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { loadChecklist, loadObservationDrafts, submitSearchScopeDraft, transitionObservation } from "./api";
import { ReviewWorkspace } from "./ReviewWorkspace";

describe("review API client", () => {
  it("loads checklist with same-origin credentials and no caching", async () => {
    const fetcher=vi.fn(async (_url:RequestInfo|URL,_init?:RequestInit)=>
      Response.json([{id:"item_a",area:"works",expectedDocument:"Expediente",status:"pending"}]));
    expect(await loadChecklist("c_a",fetcher)).toMatchObject([{id:"item_a"}]);
    expect(fetcher).toHaveBeenCalledWith("/api/commissions/c_a/checklist",expect.objectContaining({
      credentials:"same-origin",cache:"no-store"
    }));
  });

  it("loads observations only from the selected commission", async () => {
    const fetcher=vi.fn(async(_url:RequestInfo|URL,_init?:RequestInit)=>Response.json([]));
    await loadObservationDrafts("c_a",fetcher);
    expect(fetcher).toHaveBeenCalledWith("/api/commissions/c_a/observations",expect.anything());
    await expect(loadObservationDrafts("../c_b",fetcher)).rejects.toThrow();
  });

  it("submits manual search with no client-supplied reviewer, date or validation status", async () => {
    const fetcher=vi.fn(async(_url:RequestInfo|URL,_init?:RequestInit)=>
      Response.json({id:"draft_1",status:"draft"},{status:201}));
    const result=await submitSearchScopeDraft({
      commissionId:"c_a",batchId:"b_a",checklistItemId:"item_a",
      title:"Pendiente",description:"La comisión comprobó la ausencia en este lote"
    },fetcher);
    expect(result.status).toBe("draft");
    const [url,options] = fetcher.mock.calls[0]!;
    expect(url).toBe("/api/commissions/c_a/observations/drafts");
    expect(options).toMatchObject({method:"POST",credentials:"same-origin",cache:"no-store",headers:{"Idempotency-Key":expect.any(String)}});
    const data=JSON.parse(options?.body as string);
    expect(Object.keys(data).sort()).toEqual(["batchId","checklistItemId","description","title"]);
  });

  it("submits human-only review actions with an idempotency key", async () => {
    const fetcher=vi.fn(async(_url:RequestInfo|URL,_options?:RequestInit)=>
      Response.json({id:"obs_1",status:"validated",replayed:false}));
    const result=await transitionObservation({
      commissionId:"c_a",observationId:"obs_1",action:"validate",
      note:"Verifiqué los documentos y su procedencia"
    },fetcher,()=> "review_req_001");
    expect(result.status).toBe("validated");
    const [url,options]=fetcher.mock.calls[0]!;
    expect(url).toBe("/api/commissions/c_a/observations/obs_1/actions");
    expect(options).toMatchObject({method:"POST",credentials:"same-origin",cache:"no-store",
      headers:{"Idempotency-Key":"review_req_001"}});
    expect(JSON.parse(options?.body as string)).toEqual({
      action:"validate",note:"Verifiqué los documentos y su procedencia"
    });
    await expect(transitionObservation({commissionId:"c_a",observationId:"obs_1",
      action:"validate",note:"no"},fetcher)).rejects.toThrow();
  });

  it("renders review without pretending to validate an observation", () => {
    const markup=renderToStaticMarkup(<ReviewWorkspace scope={{commissionId:"c_a",batchId:"b_a"}} canDraft={true}/>);
    expect(markup).toContain("Checklist de constatación");
    expect(markup).toContain("Registrar búsqueda");
    expect(markup).toContain("No equivale a declarar una irregularidad");
  });
});
