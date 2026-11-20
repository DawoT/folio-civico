import { performance } from "node:perf_hooks";
import { join } from "node:path";
import { expect, test } from "@playwright/test";
import {
  compiledResponseForPath, loadCompiledWeb,
  summarizeRealApiLab, validateRealApiSample, type RealApiLabSample
} from "../../scripts/real-api-lab.mjs";

/**
 * PERF-005: actual signed local API handler, SQLite D1, and built frontend.
 * Playwright substitutes ONLY the compiled static JS/CSS/HTML. No /api/**
 * responses are fulfilled by the test. This is not deployed Cloudflare Access.
 */
test("PERF-005: three read-only reviewer journeys against real local signed API", async ({ browser }) => {
  test.setTimeout(100_000);
  const build = loadCompiledWeb(join(process.cwd(), "apps/web/dist"));
  const origin = String(test.info().project.use.baseURL);
  expect(origin).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  const samples: RealApiLabSample[] = [];

  for (let i = 0; i < 3; i++) {
    const context = await browser.newContext({
      viewport: { width: 1366, height: 900 },
      locale: "es-PE", serviceWorkers: "block", acceptDownloads: false
    });
    let externalRequests = 0;
    let apiErrors = 0;
    let mutations = 0;
    let apiReads = 0;
    const apiDurations = new Map<string, number[]>();
    try {
      // Build assets are served from the validated Vite dist; API requests are
      // continued unchanged to the actual demo HTTP server, not fulfilled here.
      await context.route("**/*", async route => {
        const request = route.request();
        const u = new URL(request.url());
        if (u.origin !== origin) {
          externalRequests++;
          await route.abort();
          return;
        }
        if (u.pathname.startsWith("/api/")) {
          await route.continue();
          return;
        }
        const compiled = compiledResponseForPath(u.pathname, build);
        if (compiled) {
          await route.fulfill({
            status: 200, body: compiled.body, contentType: compiled.contentType,
            headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
          });
          return;
        }
        await route.continue();
      });
      const page = await context.newPage();
      page.on("response", response => {
        if (new URL(response.url()).pathname.startsWith("/api/") && response.status() >= 400) {
          apiErrors++;
        }
      });
      page.on("requestfinished", request => {
        const u = new URL(request.url());
        if (!u.pathname.startsWith("/api/")) return;
        if (request.method() !== "GET") mutations++;
        else {
          apiReads++;
          const elapsed = request.timing().responseEnd;
          if (Number.isFinite(elapsed) && elapsed > 0) {
            const values = apiDurations.get(u.pathname) ?? [];
            values.push(elapsed);
            apiDurations.set(u.pathname, values);
          }
        }
      });

      // The guide's HttpOnly role cookie is only a local demonstration selector.
      // Its server creates an RS256 JWT and the real handler authenticates it.
      await page.goto(origin + "/__demo/switch?as=reviewer", { waitUntil: "load" });
      await expect(page.getByRole("link", { name: "Abrir mesa documental" })).toBeVisible();
      const target = await page.getByRole("link", { name: "Abrir mesa documental" }).getAttribute("href");
      expect(target).toMatch(/^\/\?commission=[A-Za-z0-9_-]+&batch=[A-Za-z0-9_-]+$/);

      const sessionStart = performance.now();
      const sessionResponse = await context.request.get(origin + "/api/session");
      const sessionApiMs = performance.now() - sessionStart;
      expect(sessionResponse.status()).toBe(200);
      const session = await sessionResponse.json();
      expect(session.subject).toBe("reviewer");
      const memberships = await context.request.get(origin + "/api/commissions");
      expect(memberships.status()).toBe(200);
      const commissions = await memberships.json();
      expect(commissions).toHaveLength(1);
      expect(commissions[0].role).toBe("member");

      const discoveryStart = performance.now();
      await page.goto(origin + "/", { waitUntil: "load" });
      await expect(page.getByLabel("Identificador de comisión").locator("option"))
        .toHaveCount(2);
      const discoveryMs = performance.now() - discoveryStart;
      const productionJs = await page.locator('script[src^="/assets/"]').count() > 0;
      const productionCss = await page.locator('link[rel="stylesheet"][href^="/assets/"]').count() > 0;

      const openStart = performance.now();
      await page.goto(origin + target!, { waitUntil: "load" });
      await expect(page.getByRole("heading", { name: "Checklist de constatación" })).toBeVisible();
      await expect(page.locator("#checklist .checklist-items > li")).toHaveCount(2);
      await expect(page.getByRole("heading", { name: "Documentos del lote" })).toBeVisible();
      await expect(page.locator(".documents-panel .document-item")).toHaveCount(1);
      await expect(page.getByText("En cuarentena").first()).toBeVisible();
      await expect(page.locator(".evidence-detail .hash")).toContainText(/[a-f0-9]{64}/);
      const openScopeMs = performance.now() - openStart;
      const documentPath = new URL(origin + target!).searchParams;
      const cid = documentPath.get("commission");
      const bid = documentPath.get("batch");
      const docsEndpoint = `/api/commissions/${cid}/batches/${bid}/documents`;
      const documentsApiMs = Math.max(...(apiDurations.get(docsEndpoint) ?? []));
      // Verify positive browser-observed request duration from the real handler.
      const sample: RealApiLabSample = {
        discoveryMs, openScopeMs, sessionApiMs, documentsApiMs,
        subject: session.subject,
        authorized: commissions[0].id === cid && commissions[0].role === "member",
        productionJs, productionCss,
        documentReady: await page.locator(".documents-panel .document-item").count() === 1,
        checklistReady: await page.locator("#checklist .checklist-items > li").count() === 2,
        apiErrors, externalRequests, mutations, apiReads
      };
      samples.push(sample);
      validateRealApiSample(sample);
    } finally {
      await context.close();
    }
  }
  const result = summarizeRealApiLab(samples);
  expect(result.navigations).toBe(3);
  console.log("PERF-005 LOCAL SIGNED API + BUILT FRONTEND (no external Access): " +
    JSON.stringify(result));
});
