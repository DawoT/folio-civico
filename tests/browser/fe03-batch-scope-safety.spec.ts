import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function openLot(page: Page, batchId = "b_a") {
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption(batchId);
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("heading", { name: "Historial de observaciones" })).toBeVisible();
}

const syntheticPdf = {
  name: "evidencia-cambio-lote.pdf",
  mimeType: "application/pdf",
  buffer: Buffer.from("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF")
};

test("changing batch selection closes old scope, clears pending file and prevents old-lot upload", async ({ page }) => {
  const api = new SyntheticPilotApi();
  api.batches.push({ id: "b_b", commissionId: "c_a", label: "Segundo lote autorizado" });
  api.documents.push({
    id: "document_a", commissionId: "c_a", batchId: "b_a",
    filename: "Original del lote previo.pdf", versionId: "version_a",
    extractionStatus: "pending", sha256: "a".repeat(64)
  });
  await api.attach(page, "author");
  await openLot(page);
  await expect(page.getByText("Original del lote previo.pdf").first()).toBeVisible();

  const input = page.getByLabel("Incorporar un expediente PDF");
  await input.setInputFiles(syntheticPdf);
  await page.getByLabel("Identificador de lote").selectOption("b_b");

  await expect(page.getByRole("region", { name: "Resumen de comisión" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Historial de observaciones" })).toHaveCount(0);
  await expect(page.getByText("Original del lote previo.pdf")).toHaveCount(0);
  await expect(input).toBeDisabled();
  await expect(page.getByRole("button", { name: "Registrar PDF" })).toBeDisabled();
  expect(await input.evaluate((element: HTMLInputElement) => element.files?.length)).toBe(0);
  const query = new URL(page.url()).searchParams;
  expect(query.has("batch")).toBe(false);
  expect(query.has("commission")).toBe(false);
  expect(api.calls.filter(call => call.method === "POST" && call.path.includes("/documents"))).toHaveLength(0);

  const scan = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  expect(scan.violations.map(issue => issue.id)).toEqual([]);

  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(input).toBeEnabled();
  expect(new URL(page.url()).searchParams.get("batch")).toBe("b_b");
  await input.setInputFiles(syntheticPdf);
  await page.getByRole("button", { name: "Registrar PDF" }).click();
  await expect(page.getByText("PDF recibido en cuarentena")).toBeVisible();
  expect(api.documents.at(-1)?.batchId).toBe("b_b");
  expect(api.documents[0]?.batchId).toBe("b_a");
  expect(api.calls.filter(call => call.method === "POST" && call.path.endsWith("/batches/b_a/documents"))).toHaveLength(0);
});

test("creating a new batch requires explicit open before any document operation", async ({ page }) => {
  const api = new SyntheticPilotApi();
  await api.attach(page, "president");
  await openLot(page);
  await page.locator("details#administracion > summary").click();
  await page.getByLabel("Nuevo lote de expedientes").fill("Segundo lote institucional sintético");
  await page.getByRole("button", { name: "Crear lote" }).click();
  await expect(page.getByText("Lote creado y seleccionado. Pulsa «Abrir lote» para continuar.")).toBeVisible();

  await expect(page.getByRole("region", { name: "Resumen de comisión" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Historial de observaciones" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Registrar PDF" })).toBeDisabled();
  expect(new URL(page.url()).searchParams.has("batch")).toBe(false);

  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("region", { name: "Resumen de comisión" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Registrar PDF" })).toBeEnabled();
  const selectedBatch = await page.getByLabel("Identificador de lote").inputValue();
  expect(selectedBatch).toMatch(/^b_created_/);
  expect(new URL(page.url()).searchParams.get("batch")).toBe(selectedBatch);
});

test("in-flight upload locks commission and batch selection to avoid scope crossing", async ({ page }) => {
  const api = new SyntheticPilotApi();
  api.batches.push({ id: "b_b", commissionId: "c_a", label: "Segundo lote autorizado" });
  await api.attach(page, "author");
  let releaseUpload = () => {};
  const blockUpload = new Promise<void>(resolve => { releaseUpload = resolve; });
  await page.route("**/api/commissions/c_a/batches/b_a/documents", async route => {
    if (route.request().method() === "POST") await blockUpload;
    await route.fallback();
  });
  await openLot(page);
  try {
    await page.getByLabel("Incorporar un expediente PDF").setInputFiles(syntheticPdf);
    await page.getByRole("button", { name: "Registrar PDF" }).click();
    await expect(page.getByRole("button", { name: "Registrando…" })).toBeVisible();
    await expect(page.getByLabel("Identificador de comisión")).toBeDisabled();
    await expect(page.getByLabel("Identificador de lote")).toBeDisabled();
  } finally {
    releaseUpload();
  }
  await expect(page.getByText("PDF recibido en cuarentena")).toBeVisible();
  await expect(page.getByLabel("Identificador de comisión")).toBeEnabled();
  await expect(page.getByLabel("Identificador de lote")).toBeEnabled();
  expect(api.documents.at(-1)?.batchId).toBe("b_a");
});
