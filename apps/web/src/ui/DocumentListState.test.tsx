import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { DocumentListState } from "./DocumentListState";

describe("UX-4.4: truth-preserving document discovery", () => {
  it("explains how to choose an authorized scope without claiming a result", () => {
    const html=renderToStaticMarkup(
      <DocumentListState phase="unselected" canUpload={false} onRetry={()=>{}}/>
    );
    expect(html).toContain("Selecciona una comisión y un lote");
    expect(html).toContain('href="#scope-commission"');
    expect(html).not.toContain("No hay documentos");
    expect(html).not.toContain("Registrar PDF");
  });

  it("does not treat a pending request as a valid zero-result search", () => {
    const html=renderToStaticMarkup(
      <DocumentListState phase="loading" canUpload onRetry={()=>{}}/>
    );
    expect(html).toContain("Consultando documentos");
    expect(html).toContain('role="status"');
    expect(html).not.toContain("No hay documentos");
    expect(html).not.toContain("Reintentar");
  });

  it("never presents unavailable results as an empty lot and offers retry", () => {
    const html=renderToStaticMarkup(
      <DocumentListState phase="failed" canUpload onRetry={()=>{}}/>
    );
    expect(html).toContain("No se pudo consultar el listado de documentos");
    expect(html).toContain("Reintentar consulta");
    expect(html).toContain('type="button"');
    expect(html).not.toContain("No hay documentos");
    expect(html).not.toContain("Seleccionar PDF");
  });

  it("a genuine empty lot offers the upload task only to a permitted role", () => {
    const allowed=renderToStaticMarkup(
      <DocumentListState phase="empty" canUpload onRetry={()=>{}}/>
    );
    expect(allowed).toContain("No hay documentos registrados en este lote");
    expect(allowed).toContain('href="#upload-pdf"');
    expect(allowed).toContain("Seleccionar PDF para registrar");

    const observer=renderToStaticMarkup(
      <DocumentListState phase="empty" canUpload={false} onRetry={()=>{}}/>
    );
    expect(observer).toContain("No hay documentos registrados en este lote");
    expect(observer).toContain("No tienes permiso para incorporar archivos");
    expect(observer).not.toContain('href="#upload-pdf"');
  });
});
