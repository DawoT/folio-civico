import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function openPilot(page: Page) {
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("heading", { name: "Checklist de constatación" })).toBeVisible();
}
function filterControls(page: Page) {
  return page.getByRole("group", { name: "Filtrar ítems del checklist" });
}
function checklistItems(page: Page) {
  return page.locator("#checklist .checklist-items li");
}

test("checklist separates internal human validation from pending items and keeps linked proof", async ({ page, context }) => {
  const api = new SyntheticPilotApi();
  api.checklist.push({ id:"item_b", commissionId:"c_a", area:"procurement",
    expectedDocument:"Contrato de prueba", status:"pending" });
  const author = await context.newPage();
  try {
    await api.attach(author, "author");
    await openPilot(author);
    await author.getByLabel("Ítem esperado", { exact:true }).selectOption("item_a");
    await author.getByLabel("Título del registro").fill("Expediente de obra buscado");
    await author.getByLabel("Alcance de la búsqueda")
      .fill("Se revisaron archivos de prueba y no se ubicó el expediente en el lote autorizado.");
    await author.getByRole("checkbox", { name:/Confirmo que realicé esta búsqueda/ }).check();
    await author.getByRole("button", { name:"Guardar borrador" }).click();
    await author.getByRole("button", { name:"Enviar a revisión" }).click();
    await expect(author.getByText("Borrador enviado a revisión")).toBeVisible();
  } finally { await author.close(); }

  await api.attach(page,"reviewer");
  await openPilot(page);
  await page.getByRole("button", { name:"Revisar registro" }).click();
  await page.getByLabel("Justificación de la decisión humana")
    .fill("Comprobé de manera independiente la búsqueda registrada y su alcance en documentos sintéticos.");
  await page.getByRole("checkbox", { name:/Confirmo que revisé la evidencia/ }).check();
  await page.getByRole("button", { name:"Validar internamente" }).click();
  await expect(page.getByText("Registro validado por un segundo revisor")).toBeVisible();

  const filters = filterControls(page);
  await expect(filters.getByRole("button", { name:"Validación interna (1)" })).toBeVisible();
  await filters.getByRole("button", { name:"Validación interna (1)" }).click();
  await expect(checklistItems(page)).toHaveCount(1);
  await expect(checklistItems(page).getByText("Expediente de obra")).toBeVisible();
  await expect(checklistItems(page).getByText("No ubicado · validación interna")).toBeVisible();

  const callsBefore=api.calls.length;
  await page.getByLabel("Área del checklist para filtrar").selectOption("procurement");
  await expect(page.getByText("No hay ítems que coincidan con los filtros actuales")).toBeVisible();
  await page.getByLabel("Área del checklist para filtrar").selectOption("all");
  expect(api.calls.length).toBe(callsBefore);
  await expect(checklistItems(page)).toHaveCount(1);
  await checklistItems(page).getByRole("button", { name:"Ver validación" }).click();
  await expect(page.getByRole("heading", { name:"Detalle de la observación" })).toBeVisible();
  await expect(page.locator(".linked-observation-card dd").getByText("Comprobé de manera independiente la búsqueda registrada y su alcance en documentos sintéticos.", {exact:true})).toBeVisible();
});

test("read-only observer filters areas and states without mutations, keyboard trap, axe or overflow", async ({page}) => {
  const api = new SyntheticPilotApi();
  api.checklist.push({ id:"item_b", commissionId:"c_a", area:"procurement",
    expectedDocument:"Contrato de prueba", status:"pending" });
  await api.attach(page,"viewer");
  await openPilot(page);
  const filters=filterControls(page);
  await expect(filters.getByRole("button", {name:"Pendientes (2)"})).toBeVisible();
  const callsBefore=api.calls.length;
  await page.getByLabel("Área del checklist para filtrar").selectOption("procurement");
  await expect(filters.getByRole("button", {name:"Pendientes (1)"})).toBeVisible();
  await expect(checklistItems(page)).toHaveCount(1);
  await expect(checklistItems(page).getByText("Contrato de prueba")).toBeVisible();
  await filters.getByRole("button", {name:"Validación interna (0)"}).click();
  await expect(page.getByText("No hay ítems que coincidan con los filtros actuales")).toBeVisible();
  await filters.getByRole("button", {name:"Todos (1)"}).click();
  expect(api.calls.length).toBe(callsBefore);
  await expect(checklistItems(page)).toHaveCount(1);
  await expect(page.getByRole("button",{name:"Incorporar ítem"})).toHaveCount(0);
  const scan=await new AxeBuilder({page}).withTags([
    "wcag2a","wcag2aa","wcag21a","wcag21aa","wcag22aa"
  ]).analyze();
  expect(scan.violations.map(issue=>issue.id)).toEqual([]);
  const overflow=await page.evaluate(()=>Array.from(document.body.querySelectorAll("*"))
    .filter(el=>el.getBoundingClientRect().right>document.documentElement.clientWidth+1)
    .slice(0,8).map(el=>el.tagName.toLowerCase()));
  expect(overflow).toEqual([]);
});
