import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { loadChecklist, loadObservationDrafts, loadObservationDetail, loadVerifiedReviewReport, createCommissionBatch, createCommissionChecklistItem, submitSearchScopeDraft, transitionObservation } from "./api";
import { ReviewWorkspace, ChecklistStatus } from "./ReviewWorkspace";
import type { ChecklistRow } from "./api";

const validExportPayload = {
  schemaVersion: 1, kind: "internal_human_review",
  generatedAt: "2026-11-20T13:00:00.000Z",
  disclaimer: "Insumo de trabajo. No constituye acta oficial.",
  commission: {id:"c_a",name:"Comisión A",status:"active"},
  completeness: {
    statuses:["validated","dismissed"], included:1,
    truncated:false, maximumPerExport:500
  },
  observations:[{
    id:"review_1",authorSubject:"author",title:"Observación revisada",
    description:"Búsqueda documentada",createdAt:"2026-11-19 11:00:00",
    status:"validated",validatedBy:"reviewer",reviewedBy:"reviewer",
    reviewedAt:"2026-11-20 12:00:00",reviewNote:"Confirmación independiente",
    evidence:[{
      type:"SEARCH_SCOPE",commissionId:"c_a",checklistItemId:"item_a",
      batchId:"batch_a",reviewerId:"author",searchedAt:"2026-11-19T11:00:00.000Z"
    }]
  }]
};

async function hashedExport(payload: unknown) {
  const serialized=JSON.stringify(payload);
  const sha256=Array.from(new Uint8Array(await crypto.subtle.digest(
    "SHA-256",new TextEncoder().encode(serialized))),
    byte=>byte.toString(16).padStart(2,"0")).join("");
  return {format:"folio-civico.review-export.v1",sha256,payload:serialized};
}

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

  it("loads an exact observation using the same-origin authenticated route, rejecting mismatched responses", async () => {
    const saved = {id:"obs_123",commissionId:"c_a",title:"Búsqueda revisada",status:"validated",evidence:[],
      reviewedBy:"eva",reviewNote:"Validación independiente suficiente."};
    const fetcher = vi.fn(async (_url:RequestInfo|URL,_opts?:RequestInit)=>Response.json(saved));
    expect(await loadObservationDetail("c_a","obs_123",fetcher)).toMatchObject(saved);
    expect(fetcher).toHaveBeenCalledWith("/api/commissions/c_a/observations/obs_123",{
      credentials:"same-origin",cache:"no-store"
    });
    await expect(loadObservationDetail("c_a","../unsafe",fetcher)).rejects.toThrow();
    const forged=vi.fn(async()=>Response.json({...saved,commissionId:"other"}));
    await expect(loadObservationDetail("c_a","obs_123",forged)).rejects.toThrow();
  });

  it("downloads a complete, correctly hashed review export from the authorized commission", async () => {
    const envelope=await hashedExport(validExportPayload);
    const {sha256,payload}=envelope;
    const fetcher=vi.fn(async()=>Response.json(envelope));
    const result=await loadVerifiedReviewReport("c_a",fetcher);
    expect(result.sha256).toBe(sha256);
    expect(result.count).toBe(1);
    expect(JSON.parse(result.file)).toEqual(envelope);
    expect(fetcher).toHaveBeenCalledWith("/api/commissions/c_a/observations/export",{
      credentials:"same-origin",cache:"no-store"
    });
    const tampered=vi.fn(async()=>Response.json({...envelope,payload:payload+" "}));
    await expect(loadVerifiedReviewReport("c_a",tampered)).rejects.toThrow();
    const wrongCommission=vi.fn(async()=>Response.json({...envelope,
      payload:JSON.stringify({...JSON.parse(payload),commission:{id:"c_b"}})}));
    await expect(loadVerifiedReviewReport("c_a",wrongCommission)).rejects.toThrow();
    await expect(loadVerifiedReviewReport("../c_b",fetcher)).rejects.toThrow();
  });

  it("refuses a rehashed dossier with cross-commission evidence or incomplete human-review provenance", async () => {
    const original=validExportPayload.observations[0]!;
    for(const modified of [
      {...validExportPayload, observations:[{
        ...original,evidence:[{...original.evidence[0],commissionId:"c_b"}]
      }]},
      {...validExportPayload, observations:[{...original,reviewedBy:""}]},
      {...validExportPayload, observations:[{...original,reviewedBy:"author"}]},
      {...validExportPayload, observations:[{...original,reviewNote:""}]},
      {...validExportPayload, observations:[{
        ...original,evidence:[{...original.evidence[0],searchedAt:"not-a-date"}]
      }]},
      {...validExportPayload, observations:[{
        ...original,evidence:[{type:"DOCUMENT_PAGE",commissionId:"c_a",
          documentVersionId:"v1",page:0,sha256:"a".repeat(64)}]
      }]},
      {...validExportPayload, observations:[original,original],
        completeness:{...validExportPayload.completeness,included:2}},
      {...validExportPayload, completeness:{
        ...validExportPayload.completeness,maximumPerExport:999
      }}
    ]) {
      const envelope=await hashedExport(modified);
      const fetcher=vi.fn(async()=>Response.json(envelope));
      await expect(loadVerifiedReviewReport("c_a",fetcher)).rejects.toThrow();
    }
  });

  it("accepts a verified empty internal report and a valid document-page citation", async () => {
    const empty=await hashedExport({
      ...validExportPayload,observations:[],
      completeness:{...validExportPayload.completeness,included:0}
    });
    expect(await loadVerifiedReviewReport("c_a",async()=>Response.json(empty)))
      .toMatchObject({count:0});
    const withPage=await hashedExport({
      ...validExportPayload,observations:[{
        ...validExportPayload.observations[0],
        evidence:[{type:"DOCUMENT_PAGE",commissionId:"c_a",
          documentVersionId:"version_a",page:1,sha256:"a".repeat(64)}]
      }]
    });
    expect(await loadVerifiedReviewReport("c_a",async()=>Response.json(withPage)))
      .toMatchObject({count:1});
  });

  it("creates authorized pilot batches and checklist items without supplying actor identity",async()=>{
    const responses=vi.fn(async (_url:RequestInfo|URL,_options?:RequestInit)=>
      Response.json({id:"created_1",replayed:false},{status:201}));
    await createCommissionBatch({commissionId:"c_a",label:"Obras y contratos"},responses,()=> "batch_create_req");
    await createCommissionChecklistItem({
      commissionId:"c_a",area:"procurement",expectedDocument:"Contrato adjudicado"
    },responses,()=> "checklist_create_req");
    const calls=responses.mock.calls;
    expect(calls[0]?.[0]).toBe("/api/commissions/c_a/batches");
    expect(calls[1]?.[0]).toBe("/api/commissions/c_a/checklist/items");
    for(const [url,options] of calls) {
      expect(url).toContain("/api/commissions/c_a/");
      expect(options).toMatchObject({
        method:"POST",credentials:"same-origin",cache:"no-store",
        headers:{"Content-Type":"application/json","Idempotency-Key":expect.any(String)}
      });
      const data=JSON.parse(options?.body as string);
      expect(data).not.toHaveProperty("actorSubject");
      expect(data).not.toHaveProperty("status");
    }
  });

  it("renders provisioning only for a president",()=>{
    const readOnly=renderToStaticMarkup(<ReviewWorkspace scope={{commissionId:"c_a",batchId:"b_a"}} canDraft={true}/>);
    const president=renderToStaticMarkup(<ReviewWorkspace scope={{commissionId:"c_a",batchId:"b_a"}} canDraft={true} canManage={true}/>);
    expect(readOnly).not.toContain("Incorporar ítem");
    expect(president).toContain("Incorporar ítem");
    expect(president).toContain("Ítem esperado del checklist");
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

  it("shows confirmed absence as an internal decision with traceable reviewer", () => {
    const item: ChecklistRow = {
      id: "item_a", area: "works", expectedDocument: "Expediente",
      status: "not_located", statusSource: "validated_search",
      validatedSearchObservationId: "obs_001", reviewedBy: "reviewer", reviewedAt: "2026-11-19 11:00:00"
    };
    const markup = renderToStaticMarkup(<ChecklistStatus item={item}/>);
    expect(markup).toContain("No ubicado");
    expect(markup).toContain("validación interna");
    expect(markup).toContain("reviewer");
    expect(markup).toContain("obs_001");
    expect(renderToStaticMarkup(<ChecklistStatus item={item} onOpenValidation={()=>{}}/>)).toContain("Ver validación");
    const pending = renderToStaticMarkup(<ChecklistStatus item={{
      ...item, status: "pending", statusSource: "stored",
      validatedSearchObservationId: null, reviewedBy: null, reviewedAt: null
    }}/>);
    expect(pending).toContain("Pendiente");
    expect(pending).not.toContain("validación interna");
  });

  it("renders review without pretending to validate an observation", () => {
    const markup=renderToStaticMarkup(<ReviewWorkspace scope={{commissionId:"c_a",batchId:"b_a"}} canDraft={true}/>);
    expect(markup).toContain("Checklist de constatación");
    expect(markup).toContain("Registrar búsqueda");
    expect(markup).toContain("No equivale a declarar una irregularidad");
  });
});
