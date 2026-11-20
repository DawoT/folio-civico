import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function openPilot(page: import("@playwright/test").Page) {
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("heading", { name: "Historial de observaciones" })).toBeVisible();
}
function inbox(page: import("@playwright/test").Page) {
  return page.getByRole("group", { name: "Filtrar observaciones cargadas" });
}

test("reviewer filters actionable records without hiding pagination or granting self-review", async ({ page, context }) => {
  const api = new SyntheticPilotApi();
  api.addHistory(31);
  const author = await context.newPage();
  try {
    await api.attach(author, "author");
    await openPilot(author);
    await author.getByLabel("Ítem esperado", { exact: true }).selectOption("item_a");
    await author.getByLabel("Título del registro").fill("Solicitud de revisión prioritaria");
    await author.getByLabel("Alcance de la búsqueda")
      .fill("Se verificaron los documentos ficticios del lote de obras y el alcance fue limitado.");
    await author.getByRole("checkbox", { name: /Confirmo que realicé esta búsqueda/ }).check();
    await author.getByRole("button", { name: "Guardar borrador" }).click();
    await author.getByRole("button", { name: "Enviar a revisión" }).click();
    await expect(author.getByText("Borrador enviado a revisión")).toBeVisible();
    // The author remains ineligible to approve their own record.
    await expect(author.getByRole("button", { name: "Revisar registro" })).toHaveCount(0);
  } finally {
    await author.close();
  }

  await api.attach(page, "reviewer");
  await openPilot(page);
  const filters = inbox(page);
  await expect(filters.getByRole("button", { name: /Para revisar \(1\)/ })).toBeVisible();
  await filters.getByRole("button", { name: /Para revisar/ }).click();
  await expect(page.locator(".observations-card li")).toHaveCount(1);
  await expect(page.getByText("Solicitud de revisión prioritaria", { exact: true })).toBeVisible();
  await expect(page.getByText("Histórico 030")).toHaveCount(0);
  const requestsBefore = api.calls.length;
  await filters.getByRole("button", { name: /Decisiones/ }).click();
  expect(api.calls.length).toBe(requestsBefore); // Client-only filter, not a new endpoint.
  await expect(page.locator(".observations-card li")).toHaveCount(24);
  await page.getByRole("button", { name: "Cargar observaciones anteriores" }).click();
  await expect(filters.getByRole("button", { name: /Decisiones \(31\)/ })).toBeVisible();
  await filters.getByRole("button", { name: /Para revisar/ }).click();
  await expect(page.locator(".observations-card li")).toHaveCount(1);
  await page.getByRole("button", { name: "Revisar registro" }).click();
  await page.getByLabel("Justificación de la decisión humana")
    .fill("Comprobé el alcance documentado de esta búsqueda ficticia de manera independiente.");
  await page.getByRole("checkbox", { name: /Confirmo que revisé la evidencia/ }).check();
  await page.getByRole("button", { name: "Validar internamente" }).click();
  await expect(page.getByText("Registro validado por un segundo revisor")).toBeVisible();
  await expect(page.getByText(/No hay solicitudes para revisar entre las observaciones cargadas/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Revisar registro" })).toHaveCount(0);
});

test("author sees only own drafts and retains all history when toggling filters", async ({ page }) => {
  const api = new SyntheticPilotApi();
  api.addHistory(2);
  await api.attach(page, "author");
  await openPilot(page);
  await page.getByLabel("Ítem esperado", { exact: true }).selectOption("item_a");
  await page.getByLabel("Título del registro").fill("Búsqueda por documentar");
  await page.getByLabel("Alcance de la búsqueda")
    .fill("Comprobé los documentos de muestra sin encontrar el esperado en este ámbito.");
  await page.getByRole("checkbox", { name: /Confirmo que realicé esta búsqueda/ }).check();
  await page.getByRole("button", { name: "Guardar borrador" }).click();
  await expect(page.getByRole("button", { name: "Enviar a revisión" })).toBeVisible();
  await inbox(page).getByRole("button", { name: /Mis borradores/ }).click();
  await expect(page.locator(".observations-card li")).toHaveCount(1);
  await expect(page.getByText("Búsqueda por documentar", { exact: true })).toBeVisible();
  await inbox(page).getByRole("button", { name: /Todas/ }).click();
  await expect(page.locator(".observations-card li")).toHaveCount(3);
});

test("observer gets read-only filters and no mutation affordances, including 320px accessibility", async ({ page }) => {
  const api = new SyntheticPilotApi();
  api.addHistory(31);
  await api.attach(page, "viewer");
  await openPilot(page);
  await expect(inbox(page).getByRole("button", { name: /Mis borradores/ })).toHaveCount(0);
  await expect(inbox(page).getByRole("button", { name: /Para revisar/ })).toHaveCount(0);
  await inbox(page).getByRole("button", { name: /Decisiones/ }).click();
  await expect(page.locator(".observations-card li")).toHaveCount(25);
  await expect(page.getByRole("button", { name: "Enviar a revisión" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Revisar registro" })).toHaveCount(0);
  const scan = await new AxeBuilder({ page }).withTags([
    "wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"
  ]).analyze();
  expect(scan.violations.map(item => item.id)).toEqual([]);
  const overflow = await page.evaluate(() =>
    Array.from(document.body.querySelectorAll("*")).filter(element =>
      element.getBoundingClientRect().right > document.documentElement.clientWidth + 1
    ).slice(0, 10).map(element => element.tagName.toLowerCase())
  );
  expect(overflow).toEqual([]);
});
