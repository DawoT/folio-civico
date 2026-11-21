import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function openLot(page:Page,batch="b_a") {
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption(batch);
  await page.getByRole("button",{name:"Abrir lote"}).click();
  await expect(page.getByRole("heading",{name:"Documentos del lote"})).toBeVisible();
}

async function audit(page:Page) {
  const scan=await new AxeBuilder({page}).withTags(["wcag2a","wcag2aa","wcag21a","wcag21aa","wcag22aa"]).analyze();
  expect(scan.violations.map(rule=>rule.id)).toEqual([]);
  const scroll=await page.evaluate(()=>
    document.documentElement.scrollWidth-document.documentElement.clientWidth
  );
  expect(scroll).toBe(0);
}

test("before scope selection, discovery offers a direct, keyboard-accessible next step",async({page})=>{
  const api=new SyntheticPilotApi();
  await api.attach(page,"viewer");
  await page.goto("/");
  const state=page.getByRole("group",{name:"Estado del listado de documentos"});
  await expect(state.getByRole("heading",{name:"Primero selecciona un lote"})).toBeVisible();
  await expect(state.getByText(/Selecciona una comisión y un lote autorizados/)).toBeVisible();
  await state.getByRole("link",{name:"Elegir comisión y lote"}).click();
  await expect(page.getByLabel("Identificador de comisión")).toBeFocused();
  await expect(page.getByRole("heading",{name:"Primero abre un lote"})).toBeVisible();
  await audit(page);
});

test("real empty response offers upload only to permitted authors, never to observers",async({page,context})=>{
  const api=new SyntheticPilotApi();
  await api.attach(page,"author");
  await page.goto("/");
  await openLot(page);
  const state=page.getByRole("group",{name:"Estado del listado de documentos"});
  await expect(state.getByText("No hay documentos registrados en este lote según la consulta completada.")).toBeVisible();
  await expect(page.getByRole("heading",{name:"Lote sin documentos registrados"})).toBeVisible();
  await state.getByRole("link",{name:"Seleccionar PDF para registrar"}).click();
  await expect(page.getByLabel("Incorporar un expediente PDF")).toBeFocused();
  await expect(page.getByRole("heading",{name:"Evidencia, no suposiciones"})).toBeVisible();
  await audit(page);

  const viewer=await context.newPage();
  try {
    await api.attach(viewer,"viewer");
    await viewer.goto("/");
    await openLot(viewer);
    const readonly=viewer.getByRole("group",{name:"Estado del listado de documentos"});
    await expect(readonly.getByText(/No tienes permiso para incorporar archivos/)).toBeVisible();
    await expect(readonly.getByRole("link",{name:"Seleccionar PDF para registrar"})).toHaveCount(0);
    await expect(viewer.getByRole("button",{name:"Registrar PDF"})).toBeDisabled();
    await audit(viewer);
  }finally{await viewer.close();}
});

test("a failed list never claims an empty lot, and retry obtains the authenticated results",async({page})=>{
  const api=new SyntheticPilotApi();
  api.documents.push({
    id:"d_a",commissionId:"c_a",batchId:"b_a",filename:"Documento sintético.pdf",
    versionId:"v_a",extractionStatus:"pending",sha256:"a".repeat(64)
  });
  await api.attach(page,"viewer");
  let fail=true;
  await page.route("**/api/commissions/c_a/batches/b_a/documents",async route=>{
    if(fail) await route.fulfill({status:503,contentType:"application/json",
      body:JSON.stringify({error:"Servicio temporalmente no disponible"})});
    else await route.fallback();
  });
  await page.goto("/");
  await openLot(page);
  const state=page.getByRole("group",{name:"Estado del listado de documentos"});
  await expect(state.getByRole("heading",{name:"Listado no disponible"})).toBeVisible();
  await expect(state.getByText(/Esto no significa que el lote esté vacío/)).toBeVisible();
  await expect(page.getByRole("heading",{name:"Evidencia no disponible"})).toBeVisible();
  await expect(page.getByRole("region",{name:"Resumen de comisión"})
    .locator(".overview-metric").filter({hasText:"Documentos del lote"}))
    .toContainText("No disponible");
  await expect(page.locator(".documents-panel .count")).toHaveText("—");
  await expect(page.getByText("No hay documentos registrados en este lote")).toHaveCount(0);
  await audit(page);

  fail=false;
  await state.getByRole("button",{name:"Reintentar consulta"}).click();
  await expect(page.getByText("Documento sintético.pdf").first()).toBeVisible();
  await expect(page.getByRole("heading",{name:"Listado no disponible"})).toHaveCount(0);
  await expect(page.locator(".documents-panel .count")).toHaveText("1");
  await expect(page.getByRole("heading",{name:"Documento sintético.pdf"})).toBeVisible();
  await expect(page.getByText("Pendiente de procesamiento").first()).toBeVisible();
  await audit(page);
});

test("switching batches hides stale document details while the new authorized response is pending",async({page})=>{
  const api=new SyntheticPilotApi();
  api.batches.push({id:"b_b",commissionId:"c_a",label:"Segundo lote sintético"});
  api.documents.push({
    id:"d_a",commissionId:"c_a",batchId:"b_a",filename:"Expediente anterior.pdf",
    versionId:"v_a",extractionStatus:"pending",sha256:"a".repeat(64)
  });
  api.documents.push({
    id:"d_b",commissionId:"c_a",batchId:"b_b",filename:"Expediente nuevo.pdf",
    versionId:"v_b",extractionStatus:"pending",sha256:"b".repeat(64)
  });
  await api.attach(page,"viewer");
  let release!:()=>void;
  const gate=new Promise<void>(resolve=>{release=resolve;});
  await page.route("**/api/commissions/c_a/batches/b_b/documents",async route=>{
    await gate;
    await route.fallback();
  });
  await page.goto("/");
  await openLot(page);
  await expect(page.getByRole("heading",{name:"Expediente anterior.pdf"})).toBeVisible();
  const requested=page.waitForRequest(req=>req.url().includes("/batches/b_b/documents"));
  await page.getByLabel("Identificador de lote").selectOption("b_b");
  await page.getByRole("button",{name:"Abrir lote"}).click();
  await requested;
  await expect(page.getByRole("heading",{name:"Expediente anterior.pdf"})).toHaveCount(0);
  await expect(page.getByRole("heading",{name:"Consultando evidencia"})).toBeVisible();
  await expect(page.locator(".documents-panel .count")).toHaveText("—");
  release();
  await expect(page.getByRole("heading",{name:"Expediente nuevo.pdf"})).toBeVisible();
  await expect(page.getByRole("heading",{name:"Expediente anterior.pdf"})).toHaveCount(0);
  await audit(page);
});
