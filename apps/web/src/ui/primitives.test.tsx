import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { readFileSync } from "node:fs";
import { Button } from "./Button";
import { InlineAlert } from "./InlineAlert";
import { StatusBadge } from "./StatusBadge";

describe("DS-002 accessible UI primitives", () => {
  it("never accidentally submits a parent form and forwards native attributes", () => {
    const html = renderToStaticMarkup(
      <Button variant="secondary" className="custom" title="Expediente" aria-label="Ver expediente">
        Abrir
      </Button>
    );
    expect(html).toContain('type="button"');
    expect(html).toContain('class="button secondary custom"');
    expect(html).toContain('aria-label="Ver expediente"');
  });

  it("preserves legacy primary button styling and prevents duplicate busy actions", () => {
    const html = renderToStaticMarkup(
      <Button variant="primary" type="submit" busy className="upload-button">Guardando…</Button>
    );
    expect(html).toContain('class="button primary upload-button"');
    expect(html).toContain('type="submit"');
    expect(html).toContain('disabled=""');
    expect(html).toContain('aria-busy="true"');
  });

  it("renders workflow states using explicit visible text instead of color alone", () => {
    const quarantined = renderToStaticMarkup(
      <StatusBadge status="quarantined">En cuarentena</StatusBadge>
    );
    const validated = renderToStaticMarkup(
      <StatusBadge status="validated">Validación interna</StatusBadge>
    );
    expect(quarantined).toContain("En cuarentena");
    expect(quarantined).toContain("status-badge--quarantined");
    expect(validated).toContain("Validación interna");
    expect(validated).toContain("status-badge--validated");
    const ready = renderToStaticMarkup(
      <StatusBadge status="ready">Texto disponible</StatusBadge>
    );
    expect(ready).toContain("Texto disponible");
    const css = readFileSync(new URL("../styles.css", import.meta.url), "utf8");
    expect(css).toMatch(/\.status-badge--ready\s*\{[^}]*var\(--fc-color-surface-subtle\)/);
  });

  it("announces errors and successes with appropriate semantics and familiar classes", () => {
    const error = renderToStaticMarkup(<InlineAlert tone="error">No se pudo continuar</InlineAlert>);
    const success = renderToStaticMarkup(<InlineAlert tone="success">Cambios guardados</InlineAlert>);
    expect(error).toContain('role="alert"');
    expect(error).toContain('class="message error"');
    expect(success).toContain('role="status"');
    expect(success).toContain('class="message success"');
    expect(success).toContain("Cambios guardados");
    const info = renderToStaticMarkup(<InlineAlert tone="info">Solo consulta</InlineAlert>);
    expect(info).toContain('role="status"');
    expect(info).toContain('class="message info"');
  });
});
