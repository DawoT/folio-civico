import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { CommissionOverview, makeReviewSummary } from "./CommissionOverview";
import type { DocumentRow, Scope } from "../api";

const scope: Scope = { commissionId: "c_a", batchId: "b_a" };
const documents: DocumentRow[] = [
  { id: "doc1", filename: "Prueba.pdf", versionId: "v1", sha256: "a".repeat(64),
    extractionStatus: "pending", pageCount: null, createdAt: "2026-11-19T00:00:00Z" },
  { id: "doc2", filename: "Prueba2.pdf", versionId: "v2", sha256: "b".repeat(64),
    extractionStatus: "ready", pageCount: 2, createdAt: "2026-11-19T00:00:00Z" }
];

function render(options?: Partial<Parameters<typeof CommissionOverview>[0]>) {
  return renderToStaticMarkup(<CommissionOverview scope={scope}
    commissionName="Comisión A" batchLabel="Obras"
    documents={documents} documentsFailed={false}
    review={makeReviewSummary(scope, [
      { status: "pending", statusSource: "stored" },
      { status: "not_located", statusSource: "validated_search" }
    ], [
      { status: "in_review", canReview: true },
      { status: "in_review", canReview: false }
    ], true)} canDraft {...options} />);
}

describe("IA-001.2 authorized commission summary", () => {
  it("derives checklist-wide and ONLY recent-review counts from existing API responses", () => {
    const summary = makeReviewSummary(scope, [
      { status: "pending", statusSource: "stored" },
      { status: "not_located", statusSource: "validated_search" },
      { status: "located", statusSource: "stored" }
    ], [
      { status: "in_review", canReview: true },
      { status: "validated", canReview: false },
      { status: "in_review", canReview: false }
    ], true);
    expect(summary).toEqual({
      scopeKey: "c_a:b_a",
      checklistTotal: 3, checklistPending: 1, internallyValidated: 1,
      reviewableRecent: 1, recentRecordCount: 3, hasOlderRecords: true,
      reviewableTotal: null, reviewableTotalLoading: false
    });
  });

  it("shows counts from real available data with explicit scope and partial-history disclaimer", () => {
    const html = render();
    expect(html).toContain("Resumen de comisión");
    expect(html).toContain("Comisión A");
    expect(html).toContain("Obras");
    expect(html).toContain("Documentos del lote");
    expect(html).toContain("Checklist pendiente");
    expect(html).toContain("Para tu revisión");
    expect(html).toContain("Solo en los últimos");
    expect(html).toContain("No es un total de la comisión");
    expect(html).toContain('href="#observaciones"');
    expect(html).not.toContain("acta oficial verificada");
    expect(html).not.toContain("100 %");
  });

  it("labels the pending extraction subset precisely without implying that other PDFs left quarantine", () => {
    const html = render();
    expect(html).toMatch(/<dt>Pendientes de procesamiento<\/dt>\s*<dd>1/);
    expect(html).toContain("Los PDF originales permanecen en cuarentena");
    expect(html).not.toContain("<dt>En cuarentena</dt>");
  });

  it("never displays zero for unknown counts, failures, or data from another scope", () => {
    const html = render({
      documents: null, documentsFailed: true,
      review: makeReviewSummary({ commissionId: "c_other", batchId: "b_other" }, [], [], false)
    });
    expect(html).toContain("Datos no disponibles");
    expect(html).toContain("—");
    expect(html).not.toContain('href="#observaciones"');
    expect(html).not.toContain('>0</dd>');
  });

  it("does not expose authoring actions to observers or infer an official finding from availability", () => {
    const html = render({ canDraft: false, review: makeReviewSummary(scope, [], [], false) });
    expect(html).not.toContain('href="#registrar-busqueda"');
    expect(html).toContain('href="#checklist"');
    expect(html).toContain("Validación interna");
  });

  it("presents an authorized commission-wide total separately from the loaded 25-record subset", () => {
    const html = render({ review: makeReviewSummary(scope, [], [
      { status: "in_review", canReview: true }
    ], true, 31) });
    expect(html).toMatch(/<dt>Para tu revisión<\/dt>\s*<dd>31/);
    expect(html).toContain("Total autorizado de la comisión");
    expect(html).toContain("Solo en los últimos 1 registros visibles (máximo 25): 1 elegibles.");
    expect(html).not.toContain("No es un total de la comisión");
  });

  it("navigates to the review inbox for older eligible records even when the first page has none", () => {
    const html = render({ review: makeReviewSummary(scope, [], [
      { status: "in_review", canReview: false }
    ], true, 31) });
    expect(html).toContain('class="overview-primary-action" href="#observaciones"');
    expect(html).toContain("Hay más registros anteriores por consultar");
  });

  it("does not trust a stale page capability when the authorized total is zero", () => {
    const html = render({ review: makeReviewSummary(scope, [
      { status: "pending", statusSource: "stored" }
    ], [{ status: "in_review", canReview: true }], false, 0) });
    expect(html).not.toContain('class="overview-primary-action" href="#observaciones"');
    expect(html).toContain('href="#registrar-busqueda"');
  });

  it("distinguishes an in-flight aggregate from an unavailable aggregate", () => {
    const loading = render({ review: makeReviewSummary(scope, [], [], false, null, true) });
    expect(loading).toContain("Consultando total autorizado de la comisión");
    expect(loading).not.toContain("Total de la comisión no disponible");
    expect(loading).not.toContain("Total autorizado de revisión no disponible");
  });

  it("never substitutes a verified zero for an unknown or failed total", () => {
    const unknown = render();
    expect(unknown).toMatch(/<dt>Para tu revisión<\/dt>\s*<dd>—/);
    expect(unknown).toContain("Total de la comisión no disponible");
    const zero = render({ review: makeReviewSummary(scope, [], [], false, 0) });
    expect(zero).toMatch(/<dt>Para tu revisión<\/dt>\s*<dd>0/);
    expect(zero).toContain("Total autorizado de la comisión");
  });

  it("prioritizes drafting when there is a pending item but no eligible recent review", () => {
    const html = render({ review: makeReviewSummary(scope, [
      { status: "pending", statusSource: "stored" }
    ], [], false) });
    expect(html).toContain('href="#registrar-busqueda"');
    expect(html).not.toContain('class="overview-primary-action" href="#observaciones"');
  });
});
