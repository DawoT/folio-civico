import { test, expect } from "@playwright/test";
import { spawnSync } from "node:child_process";

/**
 * Self-contained synthetic guided demo with a real API: no interception of
 * routes, real JWT verification and D1 membership checks. The web server
 * preloads a fictional commission and a PDF left in quarantine.
 */
test("author submits; distinct reviewer validates; checklist and JSON export follow", async ({ page, request }) => {
  await page.goto("/__demo");
  await expect(page.getByRole("heading", { name: "Folio Cívico" })).toBeVisible();
  await expect(page.getByText(/datos ficticios/i).first()).toBeVisible();
  const invalid = await request.get("/__demo/switch?as=operator", { maxRedirects: 0 });
  expect(invalid.status()).toBe(400);

  await page.goto("/__demo/switch?as=author");
  await page.getByRole("link", { name: "Abrir mesa documental" }).click();
  await expect(page.getByRole("heading", { name: "Mesa de revisión" })).toBeVisible();
  await expect(page.getByText("En cuarentena").first()).toBeVisible();
  await page.getByRole("combobox", { name: "Ítem esperado" })
    .selectOption({ label: "Expediente de contratación de obra" });
  await page.getByRole("textbox", { name: "Título del registro" })
    .fill("Expediente de obra no ubicado en la demo");
  await page.getByRole("textbox", { name: "Alcance de la búsqueda" })
    .fill("Revisé las referencias del lote sintético de obras sin localizar el expediente esperado.");
  await page.getByRole("checkbox", {
    name: "Confirmo que realicé esta búsqueda y describí su alcance, sin inferir una irregularidad."
  }).check();
  await page.getByRole("button", { name: "Guardar borrador" }).click();
  await expect(page.getByText("Expediente de obra no ubicado en la demo")).toBeVisible();
  await page.getByRole("button", { name: "Enviar a revisión" }).click();
  await expect(page.getByText("En revisión", { exact: true })).toBeVisible();

  // The author must not be able to approve the record they created.
  await expect(page.getByRole("button", { name: "Revisar registro" })).toHaveCount(0);

  await page.goto("/__demo/switch?as=reviewer");
  await page.getByRole("link", { name: "Abrir mesa documental" }).click();
  await expect(page.getByRole("button", { name: "Revisar registro" }).first()).toBeVisible();
  await page.getByRole("button", { name: "Revisar registro" }).first().click();
  await page.getByRole("textbox", { name: "Justificación de la decisión humana" })
    .fill("Confirmé personalmente el alcance de la búsqueda documentada en la comisión sintética.");
  await page.getByRole("checkbox", {
    name: "Confirmo que revisé la evidencia, soy distinto del autor y asumo esta decisión de la comisión."
  }).check();
  await page.getByRole("button", { name: "Validar internamente" }).click();
  await expect(page.getByText("No ubicado · validación interna").first()).toBeVisible();

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Exportar revisión interna (JSON)" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/folio-civico-.+\.json$/);
  const exportedFile = await download.path();
  expect(exportedFile).not.toBeNull();
  const verification = spawnSync(process.execPath,
    ["scripts/verify-review-export.mjs", exportedFile!],
    { cwd: process.cwd(), encoding: "utf8", timeout: 5000 });
  expect(verification.status, verification.stderr).toBe(0);
  expect(verification.stdout).toContain("registros:");
  await expect(page.getByText(/SHA-256/i).first()).toBeVisible();

  // Defensive guard: same process exposes neither scanned PDF text nor a PDF
  // viewer before the unavailable inspector has actually authorized pages.
  await expect(page.getByRole("heading", { name: "Revisión documental pendiente" })).toBeVisible();
});
