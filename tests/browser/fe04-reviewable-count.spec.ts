import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function openLot(page:Page,commission="c_a",batch="b_a") {
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption(commission);
  await page.getByLabel("Identificador de lote").selectOption(batch);
  await page.getByRole("button",{name:"Abrir lote"}).click();
  await expect(page.getByRole("region",{name:"Resumen de comisión"})).toBeVisible();
}

function reviewMetric(page:Page) {
  return page.getByRole("region",{name:"Resumen de comisión"})
    .locator(".overview-metric").filter({hasText:"Para tu revisión"});
}

test("31 authorized records display a commission total separate from the first 25 loaded",async({page})=>{
  const api=new SyntheticPilotApi();
  api.addHistory(31);
  for(const row of api.observations){row.status="in_review";row.authorSubject="author";}
  await api.attach(page,"reviewer");
  await openLot(page);

  await expect(reviewMetric(page).locator("dd")).toHaveText(/^31/);
  await expect(reviewMetric(page)).toContainText("Total autorizado de la comisión");
  await expect(reviewMetric(page)).toContainText("últimos 25 registros visibles");
  await expect(page.getByRole("region",{name:"Resumen de comisión"})
    .getByText(/lote abierto/)).toBeVisible();
  const history=page.locator("#observaciones");
  await expect(history.getByRole("button",{name:"Cargar observaciones anteriores"})).toBeVisible();

  const scan=await new AxeBuilder({page})
    .withTags(["wcag2a","wcag2aa","wcag21a","wcag21aa","wcag22aa"]).analyze();
  expect(scan.violations.map(rule=>rule.id)).toEqual([]);
  expect(await page.evaluate(()=>
    document.documentElement.scrollWidth-document.documentElement.clientWidth)).toBe(0);
});

test("an independent review transition refreshes the authorized total from 1 to 0",async({page})=>{
  const api=new SyntheticPilotApi();
  api.addHistory(1);
  api.observations[0]!.status="in_review";
  api.observations[0]!.authorSubject="author";
  await api.attach(page,"reviewer");
  await openLot(page);

  await expect(reviewMetric(page).locator("dd")).toHaveText(/^1/);
  await page.getByRole("button",{name:"Revisar registro"}).click();
  await page.getByLabel("Justificación de la decisión humana")
    .fill("Se verificaron independientemente los registros de la comisión sintética.");
  await page.getByRole("checkbox",{name:/Confirmo que revisé la evidencia/}).check();
  await page.getByRole("button",{name:"Validar internamente"}).click();
  await expect(page.getByText("Registro validado por un segundo revisor")).toBeVisible();
  await expect(reviewMetric(page).locator("dd")).toHaveText(/^0/);
  await expect(page.getByRole("region",{name:"Resumen de comisión"})
    .getByRole("link",{name:"Revisar solicitudes"})).toHaveCount(0);
});

test("verified zero is real for a read-only observer and cannot unlock approval",async({page})=>{
  const api=new SyntheticPilotApi();
  api.addHistory(31);
  for(const row of api.observations){row.status="in_review";}
  await api.attach(page,"viewer");
  await openLot(page);

  await expect(reviewMetric(page).locator("dd")).toHaveText(/^0/);
  await expect(reviewMetric(page)).toContainText("Total autorizado de la comisión");
  await expect(page.getByRole("link",{name:"Revisar solicitudes"})).toHaveCount(0);
  await expect(page.getByRole("button",{name:"Revisar registro"})).toHaveCount(0);
});

for(const [kind,status] of [["denied",404],["unavailable",503],["malformed",200]] as const) {
  test(`count ${kind} never becomes a verified zero`,async({page})=>{
    const api=new SyntheticPilotApi();
    api.addHistory(1);
    await api.attach(page,"reviewer");
    await page.route("**/api/commissions/c_a/observations/reviewable-count",route=>
      route.fulfill({status,contentType:"application/json",
        body:JSON.stringify(status===200?{commissionId:"c_other",count:31}:{error:"Unavailable"})})
    );
    await openLot(page);
    await expect(reviewMetric(page).locator("dd")).toHaveText(/^—/);
    await expect(reviewMetric(page)).toContainText("Total de la comisión no disponible");
    await expect(page.getByRole("region",{name:"Resumen de comisión"}))
      .toContainText("Los guiones indican información no confirmada, no cero");
    await expect(page.getByRole("heading",{name:"Historial de observaciones"})).toBeVisible();
  });
}

test("slow response for old commission never leaks into newly opened commission",async({page})=>{
  const api=new SyntheticPilotApi();
  api.addHistory(31);
  for(const row of api.observations){row.status="in_review";row.authorSubject="author";}
  api.commissions.push({id:"c_b",name:"Comisión B sintética",status:"active",members:new Map([
    ["reviewer",{subject:"reviewer",role:"member",active:true,revision:1}]
  ])});
  api.batches.push({id:"b_b",commissionId:"c_b",label:"Lote B sintético"});
  await api.attach(page,"reviewer");

  let release:()=>void=()=>{};
  const blocked=new Promise<void>(resolve=>{release=resolve;});
  await page.route("**/api/commissions/c_a/observations/reviewable-count",async route=>{
    await blocked;
    await route.fallback();
  });
  try {
    await openLot(page);
    // A delayed optional aggregate must not block the authorized checklist or history.
    await expect(page.locator("#checklist").getByText("Expediente de obra")).toBeVisible();
    await expect(reviewMetric(page).locator("dd")).toHaveText(/^—/);
    await page.getByLabel("Identificador de comisión").selectOption("c_b");
    await expect(page.getByRole("region",{name:"Resumen de comisión"})).toHaveCount(0);
    await page.getByLabel("Identificador de lote").selectOption("b_b");
    await page.getByRole("button",{name:"Abrir lote"}).click();
    await expect(reviewMetric(page).locator("dd")).toHaveText(/^0/);
  }finally{
    release();
  }
  await expect(reviewMetric(page).locator("dd")).toHaveText(/^0/);
  await expect(page.getByRole("region",{name:"Resumen de comisión"}))
    .toContainText("Comisión B sintética");
});
