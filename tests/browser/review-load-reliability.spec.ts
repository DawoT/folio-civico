import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function openLot(page: Page) {
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("heading", { name: "Constatación documental" })).toBeVisible();
}

test("checklist request fails without inventing emptiness or hiding authorized observation history", async ({ page }) => {
  const api = new SyntheticPilotApi();
  api.addHistory(1);
  await api.attach(page, "viewer");
  let fail = true;
  await page.route("**/api/commissions/c_a/checklist", async route => {
    if (fail) {
      await route.fulfill({
        status: 503, contentType: "application/json",
        body: JSON.stringify({ error: "Servicio temporalmente no disponible" })
      });
    } else await route.fallback();
  });

  await openLot(page);
  const checklist = page.locator("#checklist");
  const history = page.locator("#observaciones");
  await expect(checklist.getByRole("alert")).toContainText("No se pudo consultar el checklist");
  await expect(checklist.getByText("No hay ítems configurados para esta comisión.")).toHaveCount(0);
  await expect(history.getByText("Histórico 000")).toBeVisible();
  await expect(history.getByText("La comisión todavía no tiene observaciones registradas.")).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Resumen de comisión" })
    .locator(".overview-metric").filter({ hasText: "Checklist pendiente" })).toContainText("—");
  await expect(checklist.getByRole("button", { name: "Reintentar checklist" })).toBeVisible();

  fail = false;
  await checklist.getByRole("button", { name: "Reintentar checklist" }).click();
  await expect(checklist.getByText("Expediente de obra")).toBeVisible();
  await expect(checklist.getByRole("alert")).toHaveCount(0);
  await expect(history.getByText("Histórico 000")).toBeVisible();
});

test("observation history failure preserves the real checklist and does not claim an empty history", async ({ page }) => {
  const api = new SyntheticPilotApi();
  await api.attach(page, "author");
  let fail = true;
  await page.route("**/api/commissions/c_a/observations/history?**", async route => {
    if (fail) {
      await route.fulfill({
        status: 503, contentType: "application/json",
        body: JSON.stringify({ error: "Servicio temporalmente no disponible" })
      });
    } else await route.fallback();
  });

  await openLot(page);
  const checklist = page.locator("#checklist");
  const history = page.locator("#observaciones");
  await expect(checklist.getByText("Expediente de obra")).toBeVisible();
  await expect(history.getByRole("alert")).toContainText("No se pudo consultar el historial");
  await expect(history.getByText("La comisión todavía no tiene observaciones registradas.")).toHaveCount(0);
  await expect(history.getByRole("button", { name: "Reintentar historial" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Resumen de comisión" })
    .locator(".overview-metric").filter({ hasText: "Para tu revisión" })).toContainText("—");
  const violations = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  expect(violations.violations.map(issue => issue.id)).toEqual([]);
  expect(await page.locator("iframe, embed, object").count()).toBe(0);

  fail = false;
  await history.getByRole("button", { name: "Reintentar historial" }).click();
  await expect(history.getByText("La comisión todavía no tiene observaciones registradas.")).toBeVisible();
  await expect(history.getByRole("alert")).toHaveCount(0);
  await expect(checklist.getByText("Expediente de obra")).toBeVisible();
});


test("president cannot modify an unverified checklist while its read failed", async ({ page }) => {
  const api = new SyntheticPilotApi();
  await api.attach(page, "president");
  let fail = true;
  await page.route("**/api/commissions/c_a/checklist", async route => {
    if (fail) await route.fulfill({ status: 503, body: "unavailable" });
    else await route.fallback();
  });
  await openLot(page);
  const checklist = page.locator("#checklist");
  await expect(checklist.getByRole("alert")).toContainText("No se pudo consultar el checklist");
  await expect(page.getByLabel("Área del checklist", { exact: true })).toBeDisabled();
  await expect(page.getByLabel("Ítem esperado del checklist")).toBeDisabled();
  await expect(page.getByRole("button", { name: "Incorporar ítem" })).toBeDisabled();
  const mutationsBefore = api.calls.filter(call => call.method === "POST" && call.path.includes("/checklist/items")).length;
  expect(mutationsBefore).toBe(0);

  fail = false;
  await checklist.getByRole("button", { name: "Reintentar checklist" }).click();
  await expect(page.getByLabel("Área del checklist", { exact: true })).toBeEnabled();
  await expect(page.getByLabel("Ítem esperado del checklist")).toBeEnabled();
  await expect(checklist.getByRole("alert")).toHaveCount(0);
});

test("both requests unavailable show independent errors and recover to real results on retry", async ({ page }) => {
  const api = new SyntheticPilotApi();
  await api.attach(page, "viewer");
  let fail = true;
  await page.route("**/api/commissions/c_a/checklist", async route => {
    if (fail) await route.fulfill({ status: 503, body: "unavailable" });
    else await route.fallback();
  });
  await page.route("**/api/commissions/c_a/observations/history?**", async route => {
    if (fail) await route.fulfill({ status: 503, body: "unavailable" });
    else await route.fallback();
  });
  await openLot(page);
  const checklist = page.locator("#checklist");
  const history = page.locator("#observaciones");
  await expect(checklist.getByRole("alert")).toBeVisible();
  await expect(history.getByRole("alert")).toBeVisible();
  await expect(checklist.getByText("No hay ítems configurados para esta comisión.")).toHaveCount(0);
  await expect(history.getByText("La comisión todavía no tiene observaciones registradas.")).toHaveCount(0);

  fail = false;
  await checklist.getByRole("button", { name: "Reintentar checklist" }).click();
  await expect(checklist.getByText("Expediente de obra")).toBeVisible();
  await expect(history.getByText("La comisión todavía no tiene observaciones registradas.")).toBeVisible();
  await expect(checklist.getByRole("alert")).toHaveCount(0);
  await expect(history.getByRole("alert")).toHaveCount(0);
});
