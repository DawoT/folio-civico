import { expect, test } from "@playwright/test";
import { SyntheticPilotApi } from "./synthetic-api";

/**
 * Versioned, intentionally small visual baselines.
 * Screenshots cover only stable user-visible regions, not entire pages,
 * timestamps, document contents, session identifiers or external assets.
 *
 * Regenerate explicitly with:
 * pnpm exec playwright test tests/browser/pilot-visual.spec.ts --update-snapshots
 * Never update baselines as part of scripts/ci.sh.
 */
const screenshot = {
  animations: "disabled" as const,
  caret: "hide" as const,
  threshold: 0.2,
  maxDiffPixelRatio: 0.012
};

test("UX-5.1: initial guidance and authorized commission summary visual baselines", async ({page}) => {
  const api = new SyntheticPilotApi();
  await api.attach(page, "viewer");
  await page.goto("/");
  const initial = page.getByRole("group", { name: "Estado del listado de documentos" });
  await expect(initial.getByRole("heading", { name: "Primero selecciona un lote" })).toBeVisible();
  await expect(initial).toHaveScreenshot("pilot-initial-guidance.png", screenshot);

  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  const summary = page.getByRole("region", { name: "Resumen de comisión" });
  await expect(summary.getByText("Checklist pendiente")).toBeVisible();
  await expect(summary.getByText("Para tu revisión")).toBeVisible();
  await expect(summary).toHaveScreenshot("pilot-authorized-summary.png", screenshot);

  const empty = page.getByRole("group", { name: "Estado del listado de documentos" });
  await expect(empty.getByRole("heading", { name: "Lote sin documentos registrados" }))
    .toBeVisible();
  await expect(empty).toHaveScreenshot("pilot-authorized-empty.png", screenshot);
});

test("UX-5.1: unavailable document list has a separate verifiable visual state",async({page})=>{
  const api = new SyntheticPilotApi();
  await api.attach(page, "viewer");
  await page.route("**/api/commissions/c_a/batches/b_a/documents", async route => {
    await route.fulfill({
      status: 503, contentType: "application/json",
      body: JSON.stringify({ error: "Servicio temporalmente no disponible" })
    });
  });
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  const failure = page.getByRole("group", { name: "Estado del listado de documentos" });
  await expect(failure.getByRole("heading", { name: "Listado no disponible" })).toBeVisible();
  await expect(failure.getByRole("button", { name: "Reintentar consulta" })).toBeVisible();
  await expect(failure).toHaveScreenshot("pilot-unavailable-not-empty.png", screenshot);
});
