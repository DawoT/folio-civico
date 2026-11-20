import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function openPilot(page: Page) {
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("heading", { name: "Historial de observaciones" })).toBeVisible();
}

async function createSubmittedSearch(api: SyntheticPilotApi, context: import("@playwright/test").BrowserContext) {
  const author = await context.newPage();
  try {
    await api.attach(author, "author");
    await openPilot(author);
    await author.getByLabel("Ítem esperado", { exact: true }).selectOption("item_a");
    await author.getByLabel("Título del registro").fill("Observación para revisión contextual");
    await author.getByLabel("Alcance de la búsqueda")
      .fill("Se revisaron archivos y antecedentes ficticios del lote b_a sin localizar el ítem item_a.");
    await author.getByRole("checkbox", { name: /Confirmo que realicé esta búsqueda/ }).check();
    await author.getByRole("button", { name: "Guardar borrador" }).click();
    await author.getByRole("button", { name: "Enviar a revisión" }).click();
    await expect(author.getByText("Borrador enviado a revisión")).toBeVisible();
    await expect(author.getByRole("button", { name: "Revisar registro" })).toHaveCount(0);
  } finally { await author.close(); }
}

test("independent reviewer sees source context before deciding, without original PDF or extra fetch", async ({ page, context }) => {
  const api = new SyntheticPilotApi();
  await createSubmittedSearch(api, context);
  await api.attach(page, "reviewer");
  await openPilot(page);
  await page.getByRole("button", { name: "Revisar registro" }).click();
  const evidence = page.getByRole("region", { name: "Evidencia antes de decidir" });
  await expect(evidence).toBeVisible();
  await expect(evidence.getByText("author", { exact: true })).toBeVisible();
  await expect(evidence.getByText("Lote b_a · Ítem item_a", { exact: true })).toBeVisible();
  await expect(evidence.getByText(/no acredita por sí sola/)).toBeVisible();
  expect(await page.locator("iframe, embed, object").count()).toBe(0);
  const callsBefore = api.calls.length;
  await page.getByLabel("Justificación de la decisión humana").fill("Breve");
  await page.getByRole("checkbox", { name: /Confirmo que revisé la evidencia/ }).check();
  await expect(page.getByRole("button", { name: "Validar internamente" })).toBeDisabled();
  await page.getByLabel("Justificación de la decisión humana")
    .fill("Se verificó independientemente la búsqueda ficticia, su alcance y la identidad de quien registró la observación.");
  await expect(page.getByRole("button", { name: "Validar internamente" })).toBeEnabled();
  expect(api.calls.length).toBe(callsBefore);
  await page.getByRole("button", { name: "Validar internamente" }).click();
  await expect(page.getByText("Registro validado por un segundo revisor")).toBeVisible();
  await expect(evidence).toHaveCount(0);
  expect(api.observations[0]?.validatedBy).toBe("reviewer");
});

test("review context discloses missing references without claiming an inspection, and passes axe", async ({ page, context }) => {
  const api = new SyntheticPilotApi();
  await createSubmittedSearch(api, context);
  api.observations[0]!.evidence = [];
  await api.attach(page, "reviewer");
  await openPilot(page);
  await page.getByRole("button", { name: "Revisar registro" }).click();
  const evidence = page.getByRole("region", { name: "Evidencia antes de decidir" });
  await expect(evidence.getByText(/No hay referencias de evidencia registradas/)).toBeVisible();
  await expect(evidence.getByText(/No se accede al PDF original en cuarentena/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Validar internamente" })).toBeDisabled();
  const violations = await new AxeBuilder({ page }).withTags([
    "wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"
  ]).analyze();
  expect(violations.violations.map(x => x.id)).toEqual([]);
  const overflow = await page.evaluate(() => Array.from(document.body.querySelectorAll("*"))
    .filter(el => el.getBoundingClientRect().right > document.documentElement.clientWidth + 1)
    .slice(0, 8).map(el => el.tagName.toLowerCase()));
  expect(overflow).toEqual([]);
});
