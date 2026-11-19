import {describe,expect,it,vi} from "vitest";
import {renderToStaticMarkup} from "react-dom/server";
import {loadObservationHistory} from "./api";
import {ObservationHistoryControls,DocumentEvidenceAction} from "./ReviewWorkspace";

const observation={
  id:"obs_001",commissionId:"c_a",authorSubject:"author",
  title:"Búsqueda histórica",description:"Documento no ubicado",
  status:"validated",validatedBy:"reviewer",createdAt:"2026-11-19 13:01:00",
  reviewedBy:"reviewer",reviewedAt:"2026-11-19 13:02:00",
  evidence:[{type:"SEARCH_SCOPE",commissionId:"c_a",checklistItemId:"i",batchId:"b"}]
};

describe("safe paginated observation history client",()=>{
  it("requests page 1 and older pages without exposing tokens or losing cache protections",async()=>{
    const cursor="eyJ2IjoxLCJjIjoiY19hIiwidCI6IjIwMjYtMTEtMTkgMTM6MDE6MDAiLCJpZCI6Im9ic18wMDEifQ";
    const fetcher=vi.fn(async()=>Response.json({items:[observation],nextCursor:cursor}));
    const first=await loadObservationHistory("c_a",null,fetcher);
    expect(first.items).toHaveLength(1);
    expect(first.nextCursor).toBe(cursor);
    expect(fetcher).toHaveBeenCalledWith("/api/commissions/c_a/observations/history?limit=25",{
      credentials:"same-origin",cache:"no-store"
    });
    await loadObservationHistory("c_a",cursor,fetcher);
    expect(fetcher).toHaveBeenCalledWith(
      "/api/commissions/c_a/observations/history?limit=25&cursor="+cursor,{
        credentials:"same-origin",cache:"no-store"
      }
    );
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("rejects wrong-commission, duplicated, incomplete or oversized server pages",async()=>{
    const payload=(items:unknown[],nextCursor:string|null=null)=>
      vi.fn(async()=>Response.json({items,nextCursor}));
    await expect(loadObservationHistory("c_a",null,payload([{...observation,commissionId:"c_b"}])))
      .rejects.toThrow();
    await expect(loadObservationHistory("c_a",null,payload([observation,observation])))
      .rejects.toThrow();
    await expect(loadObservationHistory("c_a",null,payload([{...observation,evidence:null}])))
      .rejects.toThrow();
    await expect(loadObservationHistory("c_a",null,payload(Array.from({length:26},()=>observation))))
      .rejects.toThrow();
    await expect(loadObservationHistory("../a",null,payload([])))
      .rejects.toThrow();
    await expect(loadObservationHistory("c_a","evil%20cursor",payload([])))
      .rejects.toThrow();
  });

  it("navigates only inspected page references, rejecting invalid hashes and untrusted evidence",()=>{
    const valid={type:"DOCUMENT_PAGE" as const,commissionId:"c_a",documentVersionId:"version_a",page:3,sha256:"a".repeat(64)};
    const html=renderToStaticMarkup(<DocumentEvidenceAction proof={valid} onOpen={()=>{}}/>);
    expect(html).toContain("Ver página inspeccionada 3");
    expect(html).not.toContain("quarantine/");
    for(const proof of [{...valid,sha256:"bad"},{...valid,page:0},{type:"SEARCH_SCOPE" as const,commissionId:"c_a",batchId:"b"}]) {
      expect(renderToStaticMarkup(<DocumentEvidenceAction proof={proof} onOpen={()=>{}}/>)).toBe("");
    }
  });

  it("renders accessible load-more state and explicit failure without losing records",()=>{
    const html=renderToStaticMarkup(<ObservationHistoryControls
      nextCursor="opaqueCursor" loading={false} error="" onNext={()=>{}}/>);
    expect(html).toContain("Cargar observaciones anteriores");
    expect(html).toContain("type=\"button\"");
    expect(html).not.toContain("disabled");
    const waiting=renderToStaticMarkup(<ObservationHistoryControls
      nextCursor="opaqueCursor" loading={true} error="" onNext={()=>{}}/>);
    expect(waiting).toContain("Cargando historial");
    expect(waiting).toContain("disabled");
    const failed=renderToStaticMarkup(<ObservationHistoryControls
      nextCursor="opaqueCursor" loading={false} error="Error de conexión" onNext={()=>{}}/>);
    expect(failed).toContain("role=\"alert\"");
    expect(failed).toContain("Error de conexión");
    const end=renderToStaticMarkup(<ObservationHistoryControls
      nextCursor={null} loading={false} error="" onNext={()=>{}}/>);
    expect(end).not.toContain("Cargar observaciones anteriores");
  });
});
