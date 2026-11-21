import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

const versionId="ver_a";
const sha256="a".repeat(64);
const readyDocument={
  id:"doc_a", filename:"Expediente inspeccionado.pdf",
  versionId,sha256,extractionStatus:"ready",pageCount:1,
  createdAt:"2026-11-20T10:00:00.000Z"
};

async function mountTextViewer(page:Page,payload:unknown) {
  const api=new SyntheticPilotApi();
  await api.attach(page,"author");
  await page.route("**/api/commissions/c_a/batches/b_a/documents",async route=>{
    if(route.request().method()==="GET") {
      await route.fulfill({status:200,contentType:"application/json",
        body:JSON.stringify([readyDocument])});
    }else await route.fallback();
  });
  await page.route("**/api/commissions/c_a/documents/ver_a/pages",async route=>{
    await route.fulfill({status:200,contentType:"application/json",body:JSON.stringify(payload)});
  });
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button",{name:"Abrir lote"}).click();
  await expect(page.getByRole("region",{name:"Consulta de texto inspeccionado"})).toBeVisible();
  return api;
}

test("malformed inspected pages show a safe error and never offer a citation",async({page})=>{
  const api=await mountTextViewer(page,{
    versionId,sha256,pageCount:1,pages:[null]
  });
  await expect(page.getByRole("alert")).toContainText(
    "El texto inspeccionado no supera la verificación de integridad y páginas."
  );
  await expect(page.locator(".inspected-page")).toHaveCount(0);
  await expect(page.getByRole("button",{name:"Crear borrador con esta página"})).toHaveCount(0);
  await expect(page.locator("iframe,embed,object")).toHaveCount(0);
  expect(api.calls.filter(call=>call.method==="POST" && call.path.includes("/page-drafts"))).toHaveLength(0);
  const result=await new AxeBuilder({page})
    .withTags(["wcag2a","wcag2aa","wcag21a","wcag21aa","wcag22aa"]).analyze();
  expect(result.violations.map(violation=>violation.id)).toEqual([]);
});

test("valid inspected text stays available as readable text and a manual citation action",async({page})=>{
  await mountTextViewer(page,{
    versionId,sha256,pageCount:1,pages:[{page:1,text:"Extracto inspeccionado de prueba."}]
  });
  const item=page.getByRole("article",{name:"Texto de la página 1"});
  await expect(item).toBeVisible();
  await expect(item).toContainText("Extracto inspeccionado de prueba.");
  await expect(page.getByRole("button",{name:"Crear borrador con esta página"})).toBeVisible();
  await expect(page.locator("iframe,embed,object")).toHaveCount(0);
});
