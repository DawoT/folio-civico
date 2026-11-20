import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { SyntheticPilotApi } from "./synthetic-api";
import {
  type PilotTaskId, summarizeSyntheticPilotEvidence
} from "../pilot-evidence";

async function openAuthorizedLot(page: Page) {
  await page.goto("/");
  await page.getByLabel("Identificador de comisión").selectOption("c_a");
  await page.getByLabel("Identificador de lote").selectOption("b_a");
  await page.getByRole("button", { name: "Abrir lote" }).click();
  await expect(page.getByRole("region", { name: "Resumen de comisión" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Checklist de constatación" })).toBeVisible();
}

test("UX-5.1: complete synthetic multi-role pilot acceptance and evidence receipt", async ({
  page, context
}, testInfo) => {
  test.setTimeout(90_000);
  const api = new SyntheticPilotApi();
  const completed: PilotTaskId[] = [];
  const otherPages: Page[] = [];
  try {
    await test.step("Presidencia: abrir comisión y lote autorizados", async () => {
      await api.attach(page, "president");
      await openAuthorizedLot(page);
      await expect(page.getByRole("link", { name: "Administración" })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Lote sin documentos registrados" })).toBeVisible();
      completed.push("scope_opened");
    });

    const author = await context.newPage();
    otherPages.push(author);
    await api.attach(author, "author");
    await test.step("Autor: registrar PDF sintético, conservar cuarentena y no abrir original", async () => {
      await openAuthorizedLot(author);
      await author.getByLabel("Incorporar un expediente PDF").setInputFiles({
        name: "piloto-sintetico.pdf",
        mimeType: "application/pdf",
        buffer: Buffer.from("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF")
      });
      await author.getByRole("button", { name: "Registrar PDF" }).click();
      await expect(author.getByText("PDF recibido en cuarentena")).toBeVisible();
      await expect(author.getByRole("heading", { name: "piloto-sintetico.pdf" })).toBeVisible();
      await expect(author.getByText("En cuarentena").first()).toBeVisible();
      expect(await author.locator("iframe, embed, object").count()).toBe(0);
      expect(api.documents).toHaveLength(1);
      expect(api.documents[0]?.extractionStatus).toBe("pending");
      completed.push("pdf_quarantined");
    });

    await test.step("Autor: registrar búsqueda acotada como borrador", async () => {
      await author.getByLabel("Ítem esperado", { exact: true }).selectOption("item_a");
      await author.getByLabel("Título del registro").fill("Expediente buscado en lote sintético");
      await author.getByLabel("Alcance de la búsqueda").fill(
        "Se revisó el lote sintético autorizado y no se encontró el expediente esperado."
      );
      await author.getByRole("checkbox", { name: /Confirmo que realicé esta búsqueda/ }).check();
      await author.getByRole("button", { name: "Guardar borrador" }).click();
      await expect(author.getByText("Se registró un borrador de búsqueda")).toBeVisible();
      expect(api.observations).toHaveLength(1);
      expect(api.observations[0]?.status).toBe("draft");
      completed.push("draft_registered");
    });

    await test.step("Autor: enviar a revisión, sin capacidad de autorrevisión", async () => {
      await author.getByRole("button", { name: "Enviar a revisión" }).click();
      await expect(author.getByText("Borrador enviado a revisión")).toBeVisible();
      await expect(author.getByRole("button", { name: "Revisar registro" })).toHaveCount(0);
      expect(api.observations[0]?.status).toBe("in_review");
      completed.push("submitted_for_review");
    });

    const reviewer = await context.newPage();
    otherPages.push(reviewer);
    await api.attach(reviewer, "reviewer");
    await test.step("Revisor distinto: confirmar evidencia y validar internamente", async () => {
      await openAuthorizedLot(reviewer);
      const summary = reviewer.getByRole("region", { name: "Resumen de comisión" });
      await expect(summary.getByRole("link", { name: "Revisar solicitudes" })).toBeVisible();
      await reviewer.getByRole("button", { name: "Revisar registro" }).click();
      const approve = reviewer.getByRole("button", { name: "Validar internamente" });
      await expect(approve).toBeDisabled();
      await reviewer.getByLabel("Justificación de la decisión humana").fill(
        "Revisé personalmente el registro sintético y la evidencia del lote autorizado."
      );
      await reviewer.getByRole("checkbox", { name: /Confirmo que revisé la evidencia/ }).check();
      await expect(approve).toBeEnabled();
      await approve.click();
      await expect(reviewer.getByText("Registro validado por un segundo revisor")).toBeVisible();
      expect(api.observations[0]).toMatchObject({
        status: "validated", authorSubject: "author", reviewedBy: "reviewer",
        validatedBy: "reviewer"
      });
      await expect(reviewer.getByText("No ubicado · validación interna", { exact: true }))
        .toBeVisible();
      completed.push("independent_decision");
    });

    const observer = await context.newPage();
    otherPages.push(observer);
    await api.attach(observer, "viewer");
    await test.step("Observador: consultar trazabilidad sin controles de mutación", async () => {
      await openAuthorizedLot(observer);
      await expect(observer.getByRole("link", { name: "Administración" })).toHaveCount(0);
      await expect(observer.getByRole("button", { name: "Guardar borrador" })).toBeDisabled();
      await expect(observer.getByRole("button", { name: "Registrar PDF" })).toBeDisabled();
      await expect(observer.getByRole("button", { name: "Revisar registro" })).toHaveCount(0);
      await observer.getByRole("button", { name: "Ver validación" }).click();
      await expect(observer.getByRole("heading", { name: "Detalle de la observación" }))
        .toBeVisible();
      const axe = await new AxeBuilder({ page: observer }).withTags([
        "wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"
      ]).analyze();
      expect(axe.violations.map(item => item.id)).toEqual([]);
      const overflow = await observer.evaluate(() =>
        document.documentElement.scrollWidth - document.documentElement.clientWidth
      );
      expect(overflow).toBe(0);
      expect(api.calls.filter(call => call.actor === "viewer" && call.method !== "GET"))
        .toHaveLength(0);
      completed.push("observer_read_only");
    });

    await test.step("Observador: exportar solo decisiones internas con SHA-256 del payload", async () => {
      const event = observer.waitForEvent("download");
      await observer.getByRole("button", {
        name: "Exportar revisión interna (JSON)"
      }).click();
      const download = await event;
      expect(download.suggestedFilename()).toBe("folio-civico-c_a-revision-interna.json");
      const envelope = JSON.parse(await readFile(await download.path()!, "utf8")) as {
        sha256: string; payload: string;
      };
      expect(createHash("sha256").update(envelope.payload).digest("hex"))
        .toBe(envelope.sha256);
      const report = JSON.parse(envelope.payload) as {
        kind: string;
        completeness: { included: number; truncated: boolean };
        observations: Array<{ status: string; authorSubject: string; reviewedBy: string }>;
      };
      expect(report.kind).toBe("internal_human_review");
      expect(report.completeness).toEqual({ included: 1, truncated: false });
      expect(report.observations).toHaveLength(1);
      expect(report.observations[0]).toMatchObject({
        status: "validated", authorSubject: "author", reviewedBy: "reviewer"
      });
      await expect(observer.getByText("Integridad verificada. SHA-256:")).toBeVisible();
      expect(api.calls.filter(call => call.actor === "viewer" && call.method !== "GET"))
        .toHaveLength(0);
      completed.push("sha256_export_verified");
    });

    expect(summarizeSyntheticPilotEvidence(completed).automatedAcceptance).toBe("passed");
  } finally {
    const evidence = summarizeSyntheticPilotEvidence(completed);
    await testInfo.attach("synthetic-pilot-acceptance.json", {
      body: Buffer.from(JSON.stringify(evidence, null, 2)),
      contentType: "application/json"
    });
    await Promise.all(otherPages.map(async other => {
      if (!other.isClosed()) await other.close();
    }));
  }
});
