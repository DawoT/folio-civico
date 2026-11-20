import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ReviewExportPanel, type ReportExportStatus } from "./ReviewExportPanel";

const hash = "a".repeat(64);
const file = "folio-civico-c_a-revision-interna.json";
const render = (status: ReportExportStatus) => renderToStaticMarkup(
  <ReviewExportPanel status={status} onExport={() => {}}/>
);

describe("UX-3.4 trustworthy internal export experience", () => {
  it("states the institutional scope and avoids implying an official certificate before download", () => {
    const html = render({phase: "idle"});
    expect(html).toContain('aria-labelledby="review-export-title"');
    expect(html).toContain("Informe de revisión interna");
    expect(html).toContain("Exportar revisión interna (JSON)");
    expect(html).toContain("No constituye un acta oficial");
    expect(html).toContain("No incluye borradores ni archivos PDF");
    expect(html).not.toContain("Integridad verificada");
    expect(html).not.toContain("Copiar SHA-256");
  });

  it("announces verification progress and blocks repeated attempts", () => {
    const html = render({phase: "verifying"});
    expect(html).toContain('aria-busy="true"');
    expect(html).toContain("Verificando contenido y huella SHA-256");
    expect(html).toContain('role="status"');
    expect(html).toContain('disabled=""');
    expect(html).not.toContain("Integridad verificada");
    expect(html).not.toContain(hash);
  });

  it("displays a precise receipt, payload-only digest, included records and copy affordance", () => {
    const html = render({phase: "verified", sha256: hash, count: 3, filename: file});
    expect(html).toContain("Integridad verificada. SHA-256:");
    expect(html).toContain(hash);
    expect(html).toContain("3 decisiones internas");
    expect(html).toContain(file);
    expect(html).toContain("La descarga se inició");
    expect(html).toContain("contenido del informe, no del archivo contenedor");
    expect(html).toContain("no es una firma digital");
    expect(html).toContain("Copiar SHA-256");
    expect(html).toContain('role="status"');
  });

  it("represents an empty verified export as zero decisions, never a failure", () => {
    const html = render({phase: "verified", sha256: hash, count: 0, filename: file});
    expect(html).toContain("0 decisiones internas");
    expect(html).toContain("Integridad verificada");
  });

  it("uses the singular form for exactly one independently reviewed decision", () => {
    const html = render({phase: "verified", sha256: hash, count: 1, filename: file});
    expect(html).toContain("1 decisión interna");
    expect(html).not.toContain("1 decisiones internas");
  });

  it("offers retry without retaining a stale digest or download success after an error", () => {
    const html = render({phase: "error", message: "La huella SHA-256 de la exportación no coincide."});
    expect(html).toContain('role="alert"');
    expect(html).toContain("Reintentar exportación");
    expect(html).toContain("La huella SHA-256 de la exportación no coincide");
    expect(html).not.toContain("Integridad verificada");
    expect(html).not.toContain("Copiar SHA-256");
    expect(html).not.toContain(hash);
  });
});
