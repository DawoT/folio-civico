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
