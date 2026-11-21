import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { DocumentProcessingGuidance } from "./DocumentProcessingGuidance";
import type { DocumentRow } from "../api";

describe("FE-01 document processing guidance", () => {
  const render = (status: DocumentRow["extractionStatus"]) =>
    renderToStaticMarkup(<DocumentProcessingGuidance status={status} />);

  it("keeps the original PDF in quarantine in every processing state", () => {
    for (const status of ["pending", "processing", "needs_review", "failed", "ready"] as const) {
      expect(render(status)).toContain("original");
      expect(render(status)).toContain("cuarentena");
    }
  });

  it("separates technical processing states from independent human decisions", () => {
    expect(render("pending")).toContain("Pendiente de procesamiento");
    expect(render("processing")).toContain("Procesamiento técnico en curso");
    expect(render("needs_review")).toContain("Revisión técnica del procesamiento");
    expect(render("needs_review")).toContain("no es una validación institucional");
    expect(render("failed")).toContain("El procesamiento falló");
    expect(render("ready")).toContain("Texto inspeccionado disponible");
    expect(render("ready")).toContain("revisión humana independiente");
  });

  it("describes the next authorized action without linking to a quarantined PDF", () => {
    for (const status of ["pending", "processing", "needs_review", "failed"] as const) {
      const html = render(status);
      expect(html).toContain("Siguiente paso:");
      expect(html).not.toContain("<a ");
      expect(html).not.toContain("<iframe");
      expect(html).not.toContain("aprobación oficial");
    }
  });
});
