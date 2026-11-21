import { describe,expect,it,vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { InspectedPage } from "./InspectedTextViewer";
import { loadDocumentText,submitDocumentPageDraft } from "./api";

describe("inspected text client and passive rendering",()=>{
  it("reads only scoped page text with same-origin no-store",async()=>{
    const fetcher=vi.fn(async(_url:RequestInfo|URL,_init?:RequestInit)=>Response.json({
      versionId:"ver_a",sha256:"a".repeat(64),pageCount:1,
      pages:[{page:1,text:"Texto de expediente"}]
    }));
    const data=await loadDocumentText("c_a","ver_a",fetcher);
    expect(data.pages).toHaveLength(1);
    expect(fetcher).toHaveBeenCalledWith(
      "/api/commissions/c_a/documents/ver_a/pages",
      expect.objectContaining({credentials:"same-origin",cache:"no-store"})
    );
    await expect(loadDocumentText("../c_b","ver_a",fetcher)).rejects.toThrow();
    await expect(loadDocumentText("c_a","../../secret",fetcher)).rejects.toThrow();
  });
  it("accepts a complete, ordered and bounded inspected text response",async()=>{
    const payload={versionId:"ver_a",sha256:"a".repeat(64),pageCount:2,
      pages:[{page:1,text:"Primera página."},{page:2,text:"Segundo documento.\nLínea adicional."}]};
    const fetcher=vi.fn(async()=>Response.json(payload));
    expect(await loadDocumentText("c_a","ver_a",fetcher)).toEqual(payload);
  });

  it.each([
    null,
    [],
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:1,pages:[null]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:1,pages:[{page:"1",text:"texto"}]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:1,pages:[{page:1,text:null}]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:2,pages:[{page:1,text:"uno"},{page:1,text:"dos"}]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:2,pages:[{page:2,text:"dos"},{page:1,text:"uno"}]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:1,pages:[]},
    {versionId:"ver_b",sha256:"a".repeat(64),pageCount:1,pages:[{page:1,text:"texto"}]},
    {versionId:"ver_a",sha256:"A".repeat(64),pageCount:1,pages:[{page:1,text:"texto"}]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:0,pages:[]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:101,pages:[{page:1,text:"texto"}]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:1,pages:[{page:1,text:"  "}]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:1,pages:[{page:1,text:"a".repeat(8001)}]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:1,pages:[{page:1,text:"control\u0000"}]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:1,pages:[{page:1,text:"texto\u202eoculto"}]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:1,pages:[{page:1,text:"texto",unexpected:"extra"}]},
    {versionId:"ver_a",sha256:"a".repeat(64),pageCount:1,
      pages:[{page:1,text:"texto"}],r2Key:"quarantine/private.pdf"}
  ])("rejects malformed page text rather than exposing ambiguous evidence: %#",async payload=>{
    const fetcher=vi.fn(async()=>Response.json(payload));
    await expect(loadDocumentText("c_a","ver_a",fetcher))
      .rejects.toMatchObject({name:"ApiError",status:502});
  });

  it("creates an idempotent citation with no browser-controlled hash or reviewer",async()=>{
    const fetcher=vi.fn(async(_url:RequestInfo|URL,_init?:RequestInit)=>Response.json({
      id:"obs_1",status:"draft"
    },{status:201}));
    await submitDocumentPageDraft({
      commissionId:"c_a",documentVersionId:"ver_a",page:2,
      title:"Constatación del expediente",description:"Revisé el contenido de la página 2."
    },fetcher,()=>"page_req_00001");
    const [url,init]=fetcher.mock.calls[0]!;
    expect(url).toBe("/api/commissions/c_a/observations/page-drafts");
    expect(init).toMatchObject({method:"POST",credentials:"same-origin",cache:"no-store",
      headers:{"Idempotency-Key":"page_req_00001"}});
    const body=JSON.parse(init?.body as string);
    expect(Object.keys(body).sort()).toEqual(["description","documentVersionId","page","title"]);
    await expect(submitDocumentPageDraft({
      commissionId:"c_a",documentVersionId:"ver_a",page:0,
      title:"Referencia",description:"Texto"
    },fetcher)).rejects.toThrow();
  });

  it("never executes HTML from inspected text or opens the original PDF",()=>{
    const markup=renderToStaticMarkup(<InspectedPage
      page={{page:3,text:'<img src=x onerror="alert(1)"><script>evil()</script>'}}
      versionId="version_3" sha256={"a".repeat(64)}/>);
    expect(markup).toContain("&lt;img");
    expect(markup).toContain("&lt;script&gt;");
    expect(markup).not.toContain("<script>");
    expect(markup).not.toContain("<iframe");
    expect(markup).toContain("Página 3");
    expect(markup).toContain("version_3");
  });
});
