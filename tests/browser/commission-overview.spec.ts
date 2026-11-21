import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function openPilot(page: import("@playwright/test").Page) {
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("heading", { name: "Checklist de constatación" })).toBeVisible();
}

test("summary uses authoritative source counts and distinguishes quarantine from verification", async ({ page }) => {
  const api = new SyntheticPilotApi();
  api.documents.push({
    id: "doc_test", commissionId: "c_a", batchId: "b_a", filename: "Expediente ficticio.pdf",
    versionId: "v_test", extractionStatus: "pending", sha256: "a".repeat(64)
  });
  await api.attach(page, "author");
  await page.goto("/");
  await openPilot(page);
  const summary = page.getByRole("region", { name: "Resumen de comisión" });
  await expect(summary).toBeVisible();
  await expect(summary.getByText("Documentos del lote")).toBeVisible();
  await expect(summary.getByText("Pendientes de procesamiento")).toBeVisible();
  await expect(summary.getByText(/Los PDF originales permanecen en cuarentena/)).toBeVisible();
  await expect(summary.locator(".overview-metric").filter({hasText:"Pendientes de procesamiento"}))
    .toContainText("1");
  const guidance = page.locator(".evidence-panel .document-processing-guidance");
  await expect(guidance).toContainText("El PDF original permanece en cuarentena");
  await expect(guidance).toContainText("Siguiente paso: Esperar la inspección técnica autorizada");
  await expect(page.locator(".evidence-panel iframe")).toHaveCount(0);
  await expect(summary.getByText("Checklist pendiente")).toBeVisible();
  await expect(summary.getByText("Para tu revisión")).toBeVisible();
  await expect(summary.locator(".overview-metric").filter({ hasText: "Checklist pendiente" })
    .getByText("0 con Validación interna")).toBeVisible();
  await expect(summary.getByRole("link", { name: "Registrar búsqueda" })).toBeVisible();
  await expect(summary.getByText("No es un total de la comisión")).toBeVisible();
  const violations = await new AxeBuilder({ page }).withTags([
    "wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"
  ]).analyze();
  expect(violations.violations.map(item=>item.id)).toEqual([]);
  const overflow = await page.evaluate(() =>
    Array.from(document.body.querySelectorAll("*")).filter(el => {
      const rect = el.getBoundingClientRect();
      return rect.width > 0 && rect.right > document.documentElement.clientWidth + 1;
    }).map(el => el.tagName.toLowerCase()).slice(0, 6)
  );
  expect(overflow).toEqual([]);
});

test("real review transitions update summary without a duplicate dashboard fetch", async ({ page, context }) => {
  const api = new SyntheticPilotApi();
  await api.attach(page, "author");
  await page.goto("/");
  await openPilot(page);
  const authorSummary = page.getByRole("region", { name: "Resumen de comisión" });
  await expect(authorSummary.getByRole("link", { name: "Registrar búsqueda" })).toBeVisible();
  await page.getByLabel("Ítem esperado", { exact: true }).selectOption("item_a");
  await page.getByLabel("Título del registro").fill("Expediente no ubicado en la demo");
  await page.getByLabel("Alcance de la búsqueda")
    .fill("Se revisaron los documentos ficticios y no se localizó el ítem esperado.");
  await page.getByRole("checkbox", { name: /Confirmo que realicé esta búsqueda/ }).check();
  await page.getByRole("button", { name: "Guardar borrador" }).click();
  await expect(page.getByRole("button", { name: "Enviar a revisión" })).toBeVisible();
  await page.getByRole("button", { name: "Enviar a revisión" }).click();
  await expect(page.getByText("Borrador enviado a revisión")).toBeVisible();
  const reviewer = await context.newPage();
  try {
    await api.attach(reviewer, "reviewer");
    await reviewer.goto("/");
    await openPilot(reviewer);
    const summary = reviewer.getByRole("region", { name: "Resumen de comisión" });
    await expect(summary.getByRole("link", { name: "Revisar solicitudes" })).toBeVisible();
    await summary.getByRole("link", { name: "Revisar solicitudes" }).click();
    await expect(reviewer).toHaveURL(/#observaciones$/);
    await reviewer.getByRole("button", { name: "Revisar registro" }).click();
    await reviewer.getByLabel("Justificación de la decisión humana")
      .fill("Se revisaron los documentos ficticios de forma independiente.");
    await reviewer.getByRole("checkbox", { name: /Confirmo que revisé la evidencia/ }).check();
    await reviewer.getByRole("button", { name: "Validar internamente" }).click();
    await expect(reviewer.getByText("Registro validado por un segundo revisor")).toBeVisible();
    await expect(summary.getByRole("link", { name: "Revisar solicitudes" })).toHaveCount(0);
    await expect(summary.locator(".overview-metric").filter({ hasText: "Checklist pendiente" })
      .getByText("1 con Validación interna")).toBeVisible();
  } finally {
    await reviewer.close();
  }
  const checklistCalls = api.calls.filter(call =>
    call.actor === "reviewer" && call.method === "GET" && call.path === "/api/commissions/c_a/checklist"
  );
  // Existing review-workspace fetches are reused; no separate dashboard endpoint.
  expect(checklistCalls.length).toBeLessThanOrEqual(3);
});

test("observer sees read-only next action and no mutation shortcuts", async ({ page }) => {
  const api = new SyntheticPilotApi();
  api.addHistory(31);
  await api.attach(page, "viewer");
  await page.goto("/");
  await openPilot(page);
  const summary = page.getByRole("region", { name: "Resumen de comisión" });
  await expect(summary.getByRole("link", { name: "Consultar checklist" })).toBeVisible();
  await expect(summary.getByRole("link", { name: "Registrar búsqueda" })).toHaveCount(0);
  await expect(summary.getByRole("link", { name: "Revisar solicitudes" })).toHaveCount(0);
  await expect(summary.getByText("No es un total de la comisión")).toBeVisible();
});
