import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";

async function openPilot(page: Page, batchId = "b_a") {
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption(batchId);
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("region", { name: "Informe de revisión interna" })).toBeVisible();
}

test("verified report identifies the payload, included decisions and browser download without implying official approval", async ({ page }) => {
  const api = new SyntheticPilotApi();
  api.addHistory(2);
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async (text: string) => {
          (window as Window & { copiedDigest?: string }).copiedDigest = text;
        }
      }
    });
  });
  await api.attach(page, "reviewer");
  await openPilot(page);
  const panel = page.getByRole("region", { name: "Informe de revisión interna" });

  const downloadEvent = page.waitForEvent("download");
  await panel.getByRole("button", { name: "Exportar revisión interna (JSON)" }).click();
  const download = await downloadEvent;
  const manifest = JSON.parse(await readFile(await download.path()!, "utf8")) as {
    sha256: string; payload: string;
  };
  const payloadDigest = createHash("sha256").update(manifest.payload).digest("hex");
  expect(manifest.sha256).toBe(payloadDigest);
  await expect(panel.getByText("Integridad verificada. SHA-256:")).toBeVisible();
  await expect(panel.getByText("2 decisiones internas")).toBeVisible();
  await expect(panel.getByText(/La descarga se inició/)).toBeVisible();
  await expect(panel.getByText(/no del archivo contenedor JSON/)).toBeVisible();
  await expect(panel.getByText(/no es una firma digital/)).toBeVisible();

  await panel.getByRole("button", { name: "Copiar SHA-256" }).click();
  await expect(panel.getByRole("status").getByText("Huella copiada al portapapeles.")).toBeVisible();
  const copied = await page.evaluate(() => (window as Window & { copiedDigest?: string }).copiedDigest);
  expect(copied).toBe(payloadDigest);

  const issues = await new AxeBuilder({ page })
    .withTags(["wcag2a","wcag2aa","wcag21a","wcag21aa","wcag22aa"])
    .analyze();
  expect(issues.violations.map(issue => issue.id)).toEqual([]);
  const overflow = await page.evaluate(() =>
    Array.from(document.body.querySelectorAll("*")).filter(element =>
      element.getBoundingClientRect().right > document.documentElement.clientWidth + 1
    ).slice(0, 8).map(el => el.tagName.toLowerCase())
  );
  expect(overflow).toEqual([]);
});

test("a tampered export never downloads and a retry clears the error before verifying", async ({ page }) => {
  const api = new SyntheticPilotApi();
  api.addHistory(1);
  api.corruptExport = true;
  await api.attach(page, "viewer");
  await openPilot(page);
  const panel = page.getByRole("region", { name: "Informe de revisión interna" });
  const downloads: string[] = [];
  page.on("download", download => downloads.push(download.suggestedFilename()));

  await panel.getByRole("button", { name: "Exportar revisión interna (JSON)" }).click();
  await expect(panel.getByRole("alert")).toContainText("La huella SHA-256 de la exportación no coincide");
  await expect(panel.getByRole("button", { name: "Copiar SHA-256" })).toHaveCount(0);
  expect(downloads).toHaveLength(0);

  api.corruptExport = false;
  const downloadEvent = page.waitForEvent("download");
  await panel.getByRole("button", { name: "Reintentar exportación" }).click();
  await downloadEvent;
  await expect(panel.getByRole("alert")).toHaveCount(0);
  await expect(panel.getByText("1 decisión interna")).toBeVisible();
  await expect(panel.getByRole("button", { name: "Copiar SHA-256" })).toBeVisible();
  expect(downloads).toHaveLength(1);
});


test("zero-decision reports remain exportable and copy failure leaves a selectable verified digest", async ({ page }) => {
  const api = new SyntheticPilotApi();
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async () => { throw new Error("Clipboard not permitted"); } }
    });
  });
  await api.attach(page, "viewer");
  await openPilot(page);
  const panel = page.getByRole("region", { name: "Informe de revisión interna" });
  const downloadEvent = page.waitForEvent("download");
  await panel.getByRole("button", { name: "Exportar revisión interna (JSON)" }).click();
  await downloadEvent;
  await expect(panel.getByText("0 decisiones internas")).toBeVisible();
  await panel.getByRole("button", { name: "Copiar SHA-256" }).click();
  await expect(panel.getByRole("alert")).toContainText("No se pudo copiar automáticamente");
  await expect(panel.getByText("Integridad verificada. SHA-256:")).toBeVisible();
  await expect(panel.locator("code.report-digest")).toHaveText(/^[a-f0-9]{64}$/);
});

test("rapid repeated export clicks cannot produce concurrent network requests or downloads", async ({ page }) => {
  const api = new SyntheticPilotApi();
  api.addHistory(1);
  await api.attach(page, "reviewer");

  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/api/commissions/c_a/observations/export", async route => {
    await gate;
    await route.fallback();
  });
  await openPilot(page);
  const panel = page.getByRole("region", { name: "Informe de revisión interna" });
  const downloads: string[] = [];
  page.on("download", download => downloads.push(download.suggestedFilename()));

  const requestStarted = page.waitForRequest(request => request.url().includes("/observations/export"));
  await panel.getByRole("button", { name: "Exportar revisión interna (JSON)" })
    .evaluate((button: HTMLButtonElement) => { button.click(); button.click(); });
  await requestStarted;
  await expect(panel).toHaveAttribute("aria-busy", "true");
  const completed = page.waitForResponse(response => response.url().includes("/observations/export"));
  release();
  await completed;
  await expect(panel.getByText("Integridad verificada. SHA-256:")).toBeVisible();
  expect(downloads).toHaveLength(1);
  expect(api.calls.filter(call => call.path.includes("/observations/export"))).toHaveLength(1);
});

test("an obsolete report must not download after the user opens another batch", async ({ page }) => {
  const api = new SyntheticPilotApi();
  api.addHistory(1);
  api.batches.push({ id: "b_b", commissionId: "c_a", label: "Contrataciones sintéticas" });
  await api.attach(page, "reviewer");

  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/api/commissions/c_a/observations/export", async route => {
    await gate;
    await route.fallback();
  });
  await openPilot(page);
  const downloads: string[] = [];
  page.on("download", download => downloads.push(download.suggestedFilename()));
  const reportRequested = page.waitForRequest(request =>
    request.url().includes("/observations/export"));
  await page.getByRole("button", { name: "Exportar revisión interna (JSON)" }).click();
  await reportRequested;
  await expect(page.getByRole("region", { name: "Informe de revisión interna" }))
    .toHaveAttribute("aria-busy", "true");
  await page.getByLabel("Identificador de lote").selectOption("b_b");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByLabel("Identificador de lote")).toHaveValue("b_b");
  const handled = page.waitForResponse(response => response.url().includes("/observations/export"));
  release();
  await handled;
  await expect(page.getByRole("region", { name: "Informe de revisión interna" }))
    .not.toContainText("Integridad verificada");
  expect(downloads).toHaveLength(0);
});
