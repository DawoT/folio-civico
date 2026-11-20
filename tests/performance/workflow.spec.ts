import { performance } from "node:perf_hooks";
import { expect, test } from "@playwright/test";
import { SyntheticPilotApi } from "../browser/synthetic-api";
import {
  summarizeWorkflowLab, validateWorkflowSample, type WorkflowSample
} from "../../scripts/workflow-lab-metrics.mjs";

/**
 * PERF-004: user-journey automation over the real production build.
 * Role and API are synthetic (no real JWT/Access/Cloudflare). Timings include
 * Playwright's automation overhead; they are not INP or human timings.
 */
test("PERF-004: simulated authorized reviewer opens lot, paginates 40 observations and reads detail", async ({ browser }) => {
  test.setTimeout(90_000);
  const samples: WorkflowSample[] = [];

  for (let iteration = 0; iteration < 3; iteration++) {
    const context = await browser.newContext({
      viewport: { width: 1366, height: 900 },
      locale: "es-PE",
      serviceWorkers: "block"
    });
    try {
      const page = await context.newPage();
      const api = new SyntheticPilotApi();
      api.addHistory(40);
      api.documents.push({
        id: "document_fixture",
        commissionId: "c_a",
        batchId: "b_a",
        filename: "Documento sintético de consulta.pdf",
        versionId: "version_fixture",
        extractionStatus: "pending",
        sha256: "a".repeat(64)
      });
      await api.attach(page, "reviewer");
      const unexpected: string[] = [];
      page.on("request", request => {
        const url = request.url();
        if (/^https?:\/\//.test(url) && new URL(url).hostname !== "127.0.0.1") {
          unexpected.push("external");
        }
      });
      page.on("response", response => {
        if (response.url().includes("/api/") && response.status() >= 400) {
          unexpected.push("api_error");
        }
      });
      const started = performance.now();
      const response = await page.goto("/", { waitUntil: "load" });
      expect(response?.status()).toBe(200);
      await expect(page.getByLabel("Identificador de comisión"))
        .toHaveAttribute("aria-label", "Identificador de comisión");
      await expect(page.getByLabel("Identificador de comisión").locator("option[value=c_a]"))
        .toHaveCount(1);
      const discoveryMs = performance.now() - started;

      const productionAssets = await page.evaluate(() =>
        Array.from(document.querySelectorAll("script[src]"))
          .some(element => (element as HTMLScriptElement).src.includes("/assets/"))
        && Array.from(document.querySelectorAll("link[rel=stylesheet]"))
          .some(element => (element as HTMLLinkElement).href.includes("/assets/"))
      );

      const scopeStart = performance.now();
      await page.getByLabel("Identificador de comisión").selectOption("c_a");
      await page.getByLabel("Identificador de lote").selectOption("b_a");
      await page.getByRole("button", { name: "Abrir lote" }).click();
      await expect(page.getByRole("region", { name: "Resumen de comisión" })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Checklist de constatación" })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Documento sintético de consulta.pdf" })).toBeVisible();
      await expect(page.locator("#observaciones .observation-items > li")).toHaveCount(25);
      const openScopeMs = performance.now() - scopeStart;
      const firstPageItems = await page.locator("#observaciones .observation-items > li").count();

      const historyStart = performance.now();
      await page.getByRole("button", { name: "Cargar observaciones anteriores" }).click();
      await expect(page.locator("#observaciones .observation-items > li")).toHaveCount(40);
      await expect(page.getByText("Histórico 000", { exact: true })).toBeVisible();
      const historyPageMs = performance.now() - historyStart;
      const totalItems = await page.locator("#observaciones .observation-items > li").count();

      const detailStart = performance.now();
      await page.locator("#observaciones .observation-items > li")
        .filter({ hasText: "Histórico 000" })
        .getByRole("button", { name: "Ver detalle" }).click();
      await expect(page.getByRole("heading", { name: "Detalle de la observación" })).toBeVisible();
      const detailOpenMs = performance.now() - detailStart;

      const reads = api.calls.filter(call => call.method === "GET");
      const mutations = api.calls.filter(call => call.method !== "GET");
      const sawSecondPage = reads.some(call =>
        call.path.startsWith("/api/commissions/c_a/observations/history?") && call.path.includes("cursor=")
      ) && reads.some(call => call.path === "/api/commissions/c_a/observations/old_000");
      const sawChecklist = reads.some(call => call.path === "/api/commissions/c_a/checklist");
      const sawDocument = reads.some(call =>
        call.path === "/api/commissions/c_a/batches/b_a/documents"
      );

      const sample: WorkflowSample = {
        discoveryMs, openScopeMs, historyPageMs, detailOpenMs,
        firstPageItems, totalItems, sawSecondPage, sawDocument, sawChecklist,
        productionAssets, unexpectedRequests: unexpected.length,
        mutations: mutations.length
      };
      samples.push({ ...sample });
      validateWorkflowSample(sample);
    } finally {
      await context.close();
    }
  }

  const result = summarizeWorkflowLab(samples);
  expect(result.workflows).toBe(3);
  // Aggregate only: no IDs, routes, document names or raw per-run telemetry.
  console.log("PERF-004 SYNTHETIC AUTHORIZED WORKFLOW LAB (production build; no throttle): " +
    JSON.stringify(result));
});
