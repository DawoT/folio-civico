import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Field, SelectField, TextareaField } from "./Fields";
import { Card } from "./Card";
import { EmptyState, LoadingState } from "./FeedbackStates";

describe("DS-002.2 accessible form and layout primitives", () => {
  it("binds a text field to its label and composes help, error and author-provided descriptions", () => {
    const html = renderToStaticMarkup(
      <Field id="subject" label="Identidad Access" name="subject"
        required maxLength={200} hint="Usa el identificador verificado."
        error="Identidad desconocida" aria-describedby="policy-note" defaultValue="ejemplo" />
    );
    expect(html).toContain('for="subject"');
    expect(html).toContain('id="subject"');
    expect(html).toContain('name="subject"');
    expect(html).toContain('required=""');
    expect(html).toContain('maxLength="200"');
    expect(html).toContain('aria-invalid="true"');
    expect(html).toContain('aria-describedby="policy-note subject-hint subject-error"');
    expect(html).toContain('id="subject-hint"');
    expect(html).toContain('id="subject-error"');
    expect(html).toContain('role="alert"');
    expect(html).toContain('value="ejemplo"');
  });

  it("preserves a native, keyboard-usable select and its existing accessible name", () => {
    const html = renderToStaticMarkup(
      <SelectField id="commission" label="Comisión" aria-label="Identificador de comisión"
        defaultValue="c1" required>
        <option value="">Selecciona una comisión</option>
        <option value="c1">Comisión distrital</option>
      </SelectField>
    );
    expect(html).toContain('<select');
    expect(html).toContain('aria-label="Identificador de comisión"');
    expect(html).toContain('for="commission"');
    expect(html).toContain('id="commission"');
    expect(html).toContain('value="c1" selected=""');
  });

  it("uses native textarea props and keeps the error announcement associated", () => {
    const html = renderToStaticMarkup(
      <TextareaField id="review-note" label="Justificación" rows={4}
        maxLength={4000} error="Se requiere una justificación" defaultValue="Texto de prueba" />
    );
    expect(html).toContain('for="review-note"');
    expect(html).toContain('id="review-note"');
    expect(html).toContain('rows="4"');
    expect(html).toContain('maxLength="4000"');
    expect(html).toContain('aria-describedby="review-note-error"');
    expect(html).toContain('aria-invalid="true"');
    expect(html).toContain('Texto de prueba');
  });

  it("preserves semantic landmarks and labels when rendering a card", () => {
    const html = renderToStaticMarkup(
      <Card as="section" aria-labelledby="documents-title" className="documents-panel">
        <h2 id="documents-title">Documentos del lote</h2>
      </Card>
    );
    expect(html).toContain('<section');
    expect(html).toContain('aria-labelledby="documents-title"');
    expect(html).toContain('class="fc-card documents-panel"');
    expect(html).toContain('</section>');
  });

  it("announces loading and empty results without suggesting that documents are verified", () => {
    const loading = renderToStaticMarkup(
      <LoadingState>Consultando documentos…</LoadingState>
    );
    const empty = renderToStaticMarkup(
      <EmptyState>No hay documentos disponibles para este lote.</EmptyState>
    );
    for (const html of [loading, empty]) {
      expect(html).toContain('role="status"');
      expect(html).toContain('aria-live="polite"');
      expect(html).toContain('class="empty');
    }
    expect(loading).toContain("Consultando documentos");
    expect(empty).toContain("No hay documentos disponibles");
  });
});
