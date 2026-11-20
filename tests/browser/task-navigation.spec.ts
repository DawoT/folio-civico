import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";
import { installTaskNavigationProbe, navigateTaskWithDiagnostics, type TaskNavigationVisit } from "./task-navigation-diagnostics";

test("presidency opens administration intentionally instead of encountering it before documents", async ({ page }) => {
  const pilot = new SyntheticPilotApi();
  await pilot.attach(page, "president");
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  const admin = page.locator("#administracion");
  await expect(admin).toBeVisible();
  await expect(admin).not.toHaveAttribute("open");
  await expect(page.getByRole("heading", { name: "Administración de miembros" })).toBeHidden();
  await page.getByRole("link", { name: "Administración" }).click();
  await expect(admin).toHaveAttribute("open", "");
  await expect(page.getByRole("heading", { name: "Administración de miembros" })).toBeVisible();
  await expect(page).toHaveURL(/#administracion$/);
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("navigation", { name: "Áreas de trabajo" })).toBeVisible();
  const violations = await new AxeBuilder({ page }).withTags([
    "wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"
  ]).analyze();
  expect(violations.violations.map((v) => v.id)).toEqual([]);
});

test("author navigates by tasks using real anchors and preserves commission/batch on refresh", async ({ page }, testInfo) => {
  const pilot = new SyntheticPilotApi();
  await pilot.attach(page, "author");
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  const nav = page.getByRole("navigation", { name: "Áreas de trabajo" });
  await expect(nav.getByRole("link", { name: "Registrar búsqueda" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Administración" })).toHaveCount(0);
  await installTaskNavigationProbe(page);
  // Measurements are ephemeral on success; only a failing synthetic run uploads
  // numeric geometry. No DOM content, bearer tokens, cookies or full URLs.
  const visited: TaskNavigationVisit[]=[];
  for (const [label, id] of [
    ["Resumen", "resumen"],
    ["Expedientes", "expedientes"],
    ["Checklist", "checklist"],
    ["Registrar búsqueda", "registrar-busqueda"],
    ["Observaciones", "observaciones"],
    ["Informes", "informes"]
  ] as const) {
    await navigateTaskWithDiagnostics(page,nav,testInfo,{label,id},visited);
  }
  await nav.getByRole("link", { name: "Observaciones", exact: true }).click();
  await page.reload();
  await expect(page.getByLabel("Identificador de comisión")).toHaveValue("c_a");
  await expect(page.getByLabel("Identificador de lote")).toHaveValue("b_a");
  await expect(page.locator("#observaciones")).toBeVisible();
  await expect(nav.getByRole("link", { name: "Informes" })).toBeVisible();
});

test("read-only observer sees documented work but no creation or administration links", async ({ page }) => {
  const pilot = new SyntheticPilotApi();
  await pilot.attach(page, "viewer");
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  const nav = page.getByRole("navigation", { name: "Áreas de trabajo" });
  await expect(nav.getByRole("link", { name: "Checklist" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Observaciones" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "Registrar búsqueda" })).toHaveCount(0);
  await expect(nav.getByRole("link", { name: "Administración" })).toHaveCount(0);
  await expect(page.locator("#administracion")).toHaveCount(0);
});
